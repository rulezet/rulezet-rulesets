rule TTP_XOR_MULT_DOSStub_1de8 {
  strings:
    $key_1de8 = { 49 80 [2] 3d 98 [2] 7a 9a [2] 3d 8b [2] 73 87 [2] 7f 8d [2] 68 86 [2] 73 c8 [2] 4e }

  condition:
    any of them
}