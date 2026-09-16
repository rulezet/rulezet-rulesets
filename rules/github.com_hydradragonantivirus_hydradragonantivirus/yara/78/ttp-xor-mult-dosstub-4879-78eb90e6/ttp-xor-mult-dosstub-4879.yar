rule TTP_XOR_MULT_DOSStub_4879 {
  strings:
    $key_4879 = { 1c 11 [2] 68 09 [2] 2f 0b [2] 68 1a [2] 26 16 [2] 2a 1c [2] 3d 17 [2] 26 59 [2] 1b }

  condition:
    any of them
}