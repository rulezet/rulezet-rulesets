rule TTP_XOR_MULT_DOSStub_c420 {
  strings:
    $key_c420 = { 90 48 [2] e4 50 [2] a3 52 [2] e4 43 [2] aa 4f [2] a6 45 [2] b1 4e [2] aa 00 [2] 97 }

  condition:
    any of them
}