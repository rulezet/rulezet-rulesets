rule TTP_XOR_MULT_DOSStub_6fe2 {
  strings:
    $key_6fe2 = { 3b 8a [2] 4f 92 [2] 08 90 [2] 4f 81 [2] 01 8d [2] 0d 87 [2] 1a 8c [2] 01 c2 [2] 3c }

  condition:
    any of them
}