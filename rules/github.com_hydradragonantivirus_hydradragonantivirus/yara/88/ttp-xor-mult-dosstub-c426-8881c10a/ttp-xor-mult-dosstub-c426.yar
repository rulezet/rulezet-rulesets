rule TTP_XOR_MULT_DOSStub_c426 {
  strings:
    $key_c426 = { 90 4e [2] e4 56 [2] a3 54 [2] e4 45 [2] aa 49 [2] a6 43 [2] b1 48 [2] aa 06 [2] 97 }

  condition:
    any of them
}