rule TTP_XOR_MULT_DOSStub_3205 {
  strings:
    $key_3205 = { 66 6d [2] 12 75 [2] 55 77 [2] 12 66 [2] 5c 6a [2] 50 60 [2] 47 6b [2] 5c 25 [2] 61 }

  condition:
    any of them
}