rule TTP_XOR_MULT_DOSStub_c4fd {
  strings:
    $key_c4fd = { 90 95 [2] e4 8d [2] a3 8f [2] e4 9e [2] aa 92 [2] a6 98 [2] b1 93 [2] aa dd [2] 97 }

  condition:
    any of them
}