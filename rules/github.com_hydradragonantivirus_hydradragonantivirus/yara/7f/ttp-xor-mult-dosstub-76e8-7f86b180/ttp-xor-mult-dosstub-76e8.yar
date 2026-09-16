rule TTP_XOR_MULT_DOSStub_76e8 {
  strings:
    $key_76e8 = { 22 80 [2] 56 98 [2] 11 9a [2] 56 8b [2] 18 87 [2] 14 8d [2] 03 86 [2] 18 c8 [2] 25 }

  condition:
    any of them
}