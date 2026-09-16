rule TTP_XOR_MULT_DOSStub_6a55 {
  strings:
    $key_6a55 = { 3e 3d [2] 4a 25 [2] 0d 27 [2] 4a 36 [2] 04 3a [2] 08 30 [2] 1f 3b [2] 04 75 [2] 39 }

  condition:
    any of them
}