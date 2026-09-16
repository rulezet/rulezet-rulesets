rule TTP_XOR_MULT_DOSStub_2790 {
  strings:
    $key_2790 = { 73 f8 [2] 07 e0 [2] 40 e2 [2] 07 f3 [2] 49 ff [2] 45 f5 [2] 52 fe [2] 49 b0 [2] 74 }

  condition:
    any of them
}