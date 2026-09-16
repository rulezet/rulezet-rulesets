rule TTP_XOR_MULT_DOSStub_2818 {
  strings:
    $key_2818 = { 7c 70 [2] 08 68 [2] 4f 6a [2] 08 7b [2] 46 77 [2] 4a 7d [2] 5d 76 [2] 46 38 [2] 7b }

  condition:
    any of them
}