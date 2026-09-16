rule TTP_XOR_MULT_DOSStub_1df5 {
  strings:
    $key_1df5 = { 49 9d [2] 3d 85 [2] 7a 87 [2] 3d 96 [2] 73 9a [2] 7f 90 [2] 68 9b [2] 73 d5 [2] 4e }

  condition:
    any of them
}