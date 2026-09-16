rule TTP_XOR_MULT_DOSStub_1fe4 {
  strings:
    $key_1fe4 = { 4b 8c [2] 3f 94 [2] 78 96 [2] 3f 87 [2] 71 8b [2] 7d 81 [2] 6a 8a [2] 71 c4 [2] 4c }

  condition:
    any of them
}