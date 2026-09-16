rule TTP_XOR_MULT_DOSStub_4803 {
  strings:
    $key_4803 = { 1c 6b [2] 68 73 [2] 2f 71 [2] 68 60 [2] 26 6c [2] 2a 66 [2] 3d 6d [2] 26 23 [2] 1b }

  condition:
    any of them
}