rule TTP_XOR_MULT_DOSStub_adab {
  strings:
    $key_adab = { f9 c3 [2] 8d db [2] ca d9 [2] 8d c8 [2] c3 c4 [2] cf ce [2] d8 c5 [2] c3 8b [2] fe }

  condition:
    any of them
}