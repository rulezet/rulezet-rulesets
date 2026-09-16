rule TTP_XOR_MULT_DOSStub_4851 {
  strings:
    $key_4851 = { 1c 39 [2] 68 21 [2] 2f 23 [2] 68 32 [2] 26 3e [2] 2a 34 [2] 3d 3f [2] 26 71 [2] 1b }

  condition:
    any of them
}