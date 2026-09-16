rule TTP_XOR_MULT_DOSStub_5fe4 {
  strings:
    $key_5fe4 = { 0b 8c [2] 7f 94 [2] 38 96 [2] 7f 87 [2] 31 8b [2] 3d 81 [2] 2a 8a [2] 31 c4 [2] 0c }

  condition:
    any of them
}