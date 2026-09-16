rule TTP_XOR_MULT_DOSStub_2853 {
  strings:
    $key_2853 = { 7c 3b [2] 08 23 [2] 4f 21 [2] 08 30 [2] 46 3c [2] 4a 36 [2] 5d 3d [2] 46 73 [2] 7b }

  condition:
    any of them
}