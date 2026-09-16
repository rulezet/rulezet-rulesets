rule TTP_XOR_MULT_DOSStub_addd {
  strings:
    $key_addd = { f9 b5 [2] 8d ad [2] ca af [2] 8d be [2] c3 b2 [2] cf b8 [2] d8 b3 [2] c3 fd [2] fe }

  condition:
    any of them
}