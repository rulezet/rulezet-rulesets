rule TTP_XOR_MULT_DOSStub_1fe9 {
  strings:
    $key_1fe9 = { 4b 81 [2] 3f 99 [2] 78 9b [2] 3f 8a [2] 71 86 [2] 7d 8c [2] 6a 87 [2] 71 c9 [2] 4c }

  condition:
    any of them
}