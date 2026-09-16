rule TTP_XOR_MULT_DOSStub_2ae2 {
  strings:
    $key_2ae2 = { 7e 8a [2] 0a 92 [2] 4d 90 [2] 0a 81 [2] 44 8d [2] 48 87 [2] 5f 8c [2] 44 c2 [2] 79 }

  condition:
    any of them
}