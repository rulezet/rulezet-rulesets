rule TTP_XOR_MULT_DOSStub_0205 {
  strings:
    $key_0205 = { 56 6d [2] 22 75 [2] 65 77 [2] 22 66 [2] 6c 6a [2] 60 60 [2] 77 6b [2] 6c 25 [2] 51 }

  condition:
    any of them
}