rule TTP_XOR_MULT_DOSStub_4849 {
  strings:
    $key_4849 = { 1c 21 [2] 68 39 [2] 2f 3b [2] 68 2a [2] 26 26 [2] 2a 2c [2] 3d 27 [2] 26 69 [2] 1b }

  condition:
    any of them
}