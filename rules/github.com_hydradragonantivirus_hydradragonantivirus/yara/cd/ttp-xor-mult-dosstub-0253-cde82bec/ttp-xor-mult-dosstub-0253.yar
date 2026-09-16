rule TTP_XOR_MULT_DOSStub_0253 {
  strings:
    $key_0253 = { 56 3b [2] 22 23 [2] 65 21 [2] 22 30 [2] 6c 3c [2] 60 36 [2] 77 3d [2] 6c 73 [2] 51 }

  condition:
    any of them
}