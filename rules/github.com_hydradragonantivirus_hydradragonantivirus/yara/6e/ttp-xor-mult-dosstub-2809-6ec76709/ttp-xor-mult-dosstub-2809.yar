rule TTP_XOR_MULT_DOSStub_2809 {
  strings:
    $key_2809 = { 7c 61 [2] 08 79 [2] 4f 7b [2] 08 6a [2] 46 66 [2] 4a 6c [2] 5d 67 [2] 46 29 [2] 7b }

  condition:
    any of them
}