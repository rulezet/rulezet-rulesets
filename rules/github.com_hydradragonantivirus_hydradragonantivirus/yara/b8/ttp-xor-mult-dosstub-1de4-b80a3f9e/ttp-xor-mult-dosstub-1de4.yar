rule TTP_XOR_MULT_DOSStub_1de4 {
  strings:
    $key_1de4 = { 49 8c [2] 3d 94 [2] 7a 96 [2] 3d 87 [2] 73 8b [2] 7f 81 [2] 68 8a [2] 73 c4 [2] 4e }

  condition:
    any of them
}