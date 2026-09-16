rule TTP_XOR_MULT_DOSStub_0a55 {
  strings:
    $key_0a55 = { 5e 3d [2] 2a 25 [2] 6d 27 [2] 2a 36 [2] 64 3a [2] 68 30 [2] 7f 3b [2] 64 75 [2] 59 }

  condition:
    any of them
}