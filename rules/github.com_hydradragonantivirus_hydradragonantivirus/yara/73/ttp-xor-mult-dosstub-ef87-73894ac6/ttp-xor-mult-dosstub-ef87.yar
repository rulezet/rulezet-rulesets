rule TTP_XOR_MULT_DOSStub_ef87 {
  strings:
    $key_ef87 = { bb ef [2] cf f7 [2] 88 f5 [2] cf e4 [2] 81 e8 [2] 8d e2 [2] 9a e9 [2] 81 a7 [2] bc }

  condition:
    any of them
}