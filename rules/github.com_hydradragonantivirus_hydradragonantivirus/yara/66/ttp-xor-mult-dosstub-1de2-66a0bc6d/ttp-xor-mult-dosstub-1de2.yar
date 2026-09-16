rule TTP_XOR_MULT_DOSStub_1de2 {
  strings:
    $key_1de2 = { 49 8a [2] 3d 92 [2] 7a 90 [2] 3d 81 [2] 73 8d [2] 7f 87 [2] 68 8c [2] 73 c2 [2] 4e }

  condition:
    any of them
}