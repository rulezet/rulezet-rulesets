rule TTP_XOR_MULT_DOSStub_44f0 {
  strings:
    $key_44f0 = { 10 98 [2] 64 80 [2] 23 82 [2] 64 93 [2] 2a 9f [2] 26 95 [2] 31 9e [2] 2a d0 [2] 17 }

  condition:
    any of them
}