rule TTP_XOR_MULT_DOSStub_48f7 {
  strings:
    $key_48f7 = { 1c 9f [2] 68 87 [2] 2f 85 [2] 68 94 [2] 26 98 [2] 2a 92 [2] 3d 99 [2] 26 d7 [2] 1b }

  condition:
    any of them
}