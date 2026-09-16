rule TTP_XOR_MULT_DOSStub_3387 {
  strings:
    $key_3387 = { 67 ef [2] 13 f7 [2] 54 f5 [2] 13 e4 [2] 5d e8 [2] 51 e2 [2] 46 e9 [2] 5d a7 [2] 60 }

  condition:
    any of them
}