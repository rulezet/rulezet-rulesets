rule TTP_XOR_MULT_DOSStub_1df7 {
  strings:
    $key_1df7 = { 49 9f [2] 3d 87 [2] 7a 85 [2] 3d 94 [2] 73 98 [2] 7f 92 [2] 68 99 [2] 73 d7 [2] 4e }

  condition:
    any of them
}