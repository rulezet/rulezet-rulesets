rule TTP_XOR_MULT_DOSStub_7fe2 {
  strings:
    $key_7fe2 = { 2b 8a [2] 5f 92 [2] 18 90 [2] 5f 81 [2] 11 8d [2] 1d 87 [2] 0a 8c [2] 11 c2 [2] 2c }

  condition:
    any of them
}