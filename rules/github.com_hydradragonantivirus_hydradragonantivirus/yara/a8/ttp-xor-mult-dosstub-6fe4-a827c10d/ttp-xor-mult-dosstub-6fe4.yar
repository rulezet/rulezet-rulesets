rule TTP_XOR_MULT_DOSStub_6fe4 {
  strings:
    $key_6fe4 = { 3b 8c [2] 4f 94 [2] 08 96 [2] 4f 87 [2] 01 8b [2] 0d 81 [2] 1a 8a [2] 01 c4 [2] 3c }

  condition:
    any of them
}