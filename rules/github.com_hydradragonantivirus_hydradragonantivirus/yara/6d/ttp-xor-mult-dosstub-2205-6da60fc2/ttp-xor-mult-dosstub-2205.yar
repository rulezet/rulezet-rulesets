rule TTP_XOR_MULT_DOSStub_2205 {
  strings:
    $key_2205 = { 76 6d [2] 02 75 [2] 45 77 [2] 02 66 [2] 4c 6a [2] 40 60 [2] 57 6b [2] 4c 25 [2] 71 }

  condition:
    any of them
}