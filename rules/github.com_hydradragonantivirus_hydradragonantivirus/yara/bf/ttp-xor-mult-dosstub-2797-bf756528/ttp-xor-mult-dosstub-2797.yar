rule TTP_XOR_MULT_DOSStub_2797 {
  strings:
    $key_2797 = { 73 ff [2] 07 e7 [2] 40 e5 [2] 07 f4 [2] 49 f8 [2] 45 f2 [2] 52 f9 [2] 49 b7 [2] 74 }

  condition:
    any of them
}