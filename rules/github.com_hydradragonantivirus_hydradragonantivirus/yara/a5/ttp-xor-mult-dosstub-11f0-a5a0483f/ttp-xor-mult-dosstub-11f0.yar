rule TTP_XOR_MULT_DOSStub_11f0 {
  strings:
    $key_11f0 = { 45 98 [2] 31 80 [2] 76 82 [2] 31 93 [2] 7f 9f [2] 73 95 [2] 64 9e [2] 7f d0 [2] 42 }

  condition:
    any of them
}