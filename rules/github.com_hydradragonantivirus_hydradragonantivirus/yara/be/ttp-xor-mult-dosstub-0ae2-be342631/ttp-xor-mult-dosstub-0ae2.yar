rule TTP_XOR_MULT_DOSStub_0ae2 {
  strings:
    $key_0ae2 = { 5e 8a [2] 2a 92 [2] 6d 90 [2] 2a 81 [2] 64 8d [2] 68 87 [2] 7f 8c [2] 64 c2 [2] 59 }

  condition:
    any of them
}