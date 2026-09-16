rule TTP_XOR_MULT_DOSStub_3319 {
  strings:
    $key_3319 = { 67 71 [2] 13 69 [2] 54 6b [2] 13 7a [2] 5d 76 [2] 51 7c [2] 46 77 [2] 5d 39 [2] 60 }

  condition:
    any of them
}