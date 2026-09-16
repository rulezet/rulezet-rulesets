rule TTP_XOR_MULT_DOSStub_48f6 {
  strings:
    $key_48f6 = { 1c 9e [2] 68 86 [2] 2f 84 [2] 68 95 [2] 26 99 [2] 2a 93 [2] 3d 98 [2] 26 d6 [2] 1b }

  condition:
    any of them
}