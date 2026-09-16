rule TTP_XOR_MULT_DOSStub_c416 {
  strings:
    $key_c416 = { 90 7e [2] e4 66 [2] a3 64 [2] e4 75 [2] aa 79 [2] a6 73 [2] b1 78 [2] aa 36 [2] 97 }

  condition:
    any of them
}