rule TTP_XOR_MULT_DOSStub_2fe2 {
  strings:
    $key_2fe2 = { 7b 8a [2] 0f 92 [2] 48 90 [2] 0f 81 [2] 41 8d [2] 4d 87 [2] 5a 8c [2] 41 c2 [2] 7c }

  condition:
    any of them
}