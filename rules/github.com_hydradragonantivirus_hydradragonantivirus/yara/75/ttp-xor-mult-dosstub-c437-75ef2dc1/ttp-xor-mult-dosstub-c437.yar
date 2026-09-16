rule TTP_XOR_MULT_DOSStub_c437 {
  strings:
    $key_c437 = { 90 5f [2] e4 47 [2] a3 45 [2] e4 54 [2] aa 58 [2] a6 52 [2] b1 59 [2] aa 17 [2] 97 }

  condition:
    any of them
}