rule TTP_XOR_MULT_DOSStub_c42d {
  strings:
    $key_c42d = { 90 45 [2] e4 5d [2] a3 5f [2] e4 4e [2] aa 42 [2] a6 48 [2] b1 43 [2] aa 0d [2] 97 }

  condition:
    any of them
}