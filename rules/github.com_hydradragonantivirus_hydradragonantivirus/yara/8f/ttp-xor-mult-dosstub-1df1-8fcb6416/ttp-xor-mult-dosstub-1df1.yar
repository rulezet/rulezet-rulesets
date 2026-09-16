rule TTP_XOR_MULT_DOSStub_1df1 {
  strings:
    $key_1df1 = { 49 99 [2] 3d 81 [2] 7a 83 [2] 3d 92 [2] 73 9e [2] 7f 94 [2] 68 9f [2] 73 d1 [2] 4e }

  condition:
    any of them
}