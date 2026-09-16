rule TTP_XOR_MULT_DOSStub_4705 {
  strings:
    $key_4705 = { 13 6d [2] 67 75 [2] 20 77 [2] 67 66 [2] 29 6a [2] 25 60 [2] 32 6b [2] 29 25 [2] 14 }

  condition:
    any of them
}