rule TTP_XOR_MULT_DOSStub_c441 {
  strings:
    $key_c441 = { 90 29 [2] e4 31 [2] a3 33 [2] e4 22 [2] aa 2e [2] a6 24 [2] b1 2f [2] aa 61 [2] 97 }

  condition:
    any of them
}