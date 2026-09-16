rule TTP_XOR_MULT_DOSStub_ef80 {
  strings:
    $key_ef80 = { bb e8 [2] cf f0 [2] 88 f2 [2] cf e3 [2] 81 ef [2] 8d e5 [2] 9a ee [2] 81 a0 [2] bc }

  condition:
    any of them
}