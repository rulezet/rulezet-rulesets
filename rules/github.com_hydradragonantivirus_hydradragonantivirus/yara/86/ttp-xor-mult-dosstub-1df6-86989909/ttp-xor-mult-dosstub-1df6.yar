rule TTP_XOR_MULT_DOSStub_1df6 {
  strings:
    $key_1df6 = { 49 9e [2] 3d 86 [2] 7a 84 [2] 3d 95 [2] 73 99 [2] 7f 93 [2] 68 98 [2] 73 d6 [2] 4e }

  condition:
    any of them
}