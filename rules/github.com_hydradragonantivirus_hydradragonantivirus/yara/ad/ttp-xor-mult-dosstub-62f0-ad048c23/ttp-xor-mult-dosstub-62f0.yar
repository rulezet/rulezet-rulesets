rule TTP_XOR_MULT_DOSStub_62f0 {
  strings:
    $key_62f0 = { 36 98 [2] 42 80 [2] 05 82 [2] 42 93 [2] 0c 9f [2] 00 95 [2] 17 9e [2] 0c d0 [2] 31 }

  condition:
    any of them
}