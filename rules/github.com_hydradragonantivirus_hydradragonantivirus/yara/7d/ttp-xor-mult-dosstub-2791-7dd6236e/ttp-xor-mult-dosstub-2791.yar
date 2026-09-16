rule TTP_XOR_MULT_DOSStub_2791 {
  strings:
    $key_2791 = { 73 f9 [2] 07 e1 [2] 40 e3 [2] 07 f2 [2] 49 fe [2] 45 f4 [2] 52 ff [2] 49 b1 [2] 74 }

  condition:
    any of them
}