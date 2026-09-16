rule TTP_XOR_MULT_DOSStub_addb {
  strings:
    $key_addb = { f9 b3 [2] 8d ab [2] ca a9 [2] 8d b8 [2] c3 b4 [2] cf be [2] d8 b5 [2] c3 fb [2] fe }

  condition:
    any of them
}