rule TTP_XOR_MULT_DOSStub_1fe2 {
  strings:
    $key_1fe2 = { 4b 8a [2] 3f 92 [2] 78 90 [2] 3f 81 [2] 71 8d [2] 7d 87 [2] 6a 8c [2] 71 c2 [2] 4c }

  condition:
    any of them
}