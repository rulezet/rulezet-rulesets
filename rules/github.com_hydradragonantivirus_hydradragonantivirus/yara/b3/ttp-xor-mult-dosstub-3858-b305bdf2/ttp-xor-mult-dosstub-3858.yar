rule TTP_XOR_MULT_DOSStub_3858 {
  strings:
    $key_3858 = { 6c 30 [2] 18 28 [2] 5f 2a [2] 18 3b [2] 56 37 [2] 5a 3d [2] 4d 36 [2] 56 78 [2] 6b }

  condition:
    any of them
}