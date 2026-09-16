rule TTP_XOR_MULT_DOSStub_ef8b {
  strings:
    $key_ef8b = { bb e3 [2] cf fb [2] 88 f9 [2] cf e8 [2] 81 e4 [2] 8d ee [2] 9a e5 [2] 81 ab [2] bc }

  condition:
    any of them
}