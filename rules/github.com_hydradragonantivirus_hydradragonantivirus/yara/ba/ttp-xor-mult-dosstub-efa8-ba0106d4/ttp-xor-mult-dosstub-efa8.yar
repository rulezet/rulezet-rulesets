rule TTP_XOR_MULT_DOSStub_efa8 {
  strings:
    $key_efa8 = { bb c0 [2] cf d8 [2] 88 da [2] cf cb [2] 81 c7 [2] 8d cd [2] 9a c6 [2] 81 88 [2] bc }

  condition:
    any of them
}