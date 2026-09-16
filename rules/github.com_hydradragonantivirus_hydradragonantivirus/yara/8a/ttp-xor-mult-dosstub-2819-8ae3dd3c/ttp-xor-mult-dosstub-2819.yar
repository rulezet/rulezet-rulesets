rule TTP_XOR_MULT_DOSStub_2819 {
  strings:
    $key_2819 = { 7c 71 [2] 08 69 [2] 4f 6b [2] 08 7a [2] 46 76 [2] 4a 7c [2] 5d 77 [2] 46 39 [2] 7b }

  condition:
    any of them
}