rule TTP_XOR_MULT_DOSStub_c42b {
  strings:
    $key_c42b = { 90 43 [2] e4 5b [2] a3 59 [2] e4 48 [2] aa 44 [2] a6 4e [2] b1 45 [2] aa 0b [2] 97 }

  condition:
    any of them
}