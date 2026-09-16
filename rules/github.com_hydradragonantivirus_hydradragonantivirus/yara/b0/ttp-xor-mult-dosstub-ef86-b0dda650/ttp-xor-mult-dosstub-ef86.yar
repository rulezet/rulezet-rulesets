rule TTP_XOR_MULT_DOSStub_ef86 {
  strings:
    $key_ef86 = { bb ee [2] cf f6 [2] 88 f4 [2] cf e5 [2] 81 e9 [2] 8d e3 [2] 9a e8 [2] 81 a6 [2] bc }

  condition:
    any of them
}