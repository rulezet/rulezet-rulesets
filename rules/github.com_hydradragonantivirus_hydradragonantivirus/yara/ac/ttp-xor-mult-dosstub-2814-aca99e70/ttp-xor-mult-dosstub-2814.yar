rule TTP_XOR_MULT_DOSStub_2814 {
  strings:
    $key_2814 = { 7c 7c [2] 08 64 [2] 4f 66 [2] 08 77 [2] 46 7b [2] 4a 71 [2] 5d 7a [2] 46 34 [2] 7b }

  condition:
    any of them
}