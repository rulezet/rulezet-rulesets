rule TTP_XOR_MULT_DOSStub_48f1 {
  strings:
    $key_48f1 = { 1c 99 [2] 68 81 [2] 2f 83 [2] 68 92 [2] 26 9e [2] 2a 94 [2] 3d 9f [2] 26 d1 [2] 1b }

  condition:
    any of them
}