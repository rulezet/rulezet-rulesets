rule TTP_XOR_MULT_DOSStub_1f15 {
  strings:
    $key_1f15 = { 4b 7d [2] 3f 65 [2] 78 67 [2] 3f 76 [2] 71 7a [2] 7d 70 [2] 6a 7b [2] 71 35 [2] 4c }

  condition:
    any of them
}