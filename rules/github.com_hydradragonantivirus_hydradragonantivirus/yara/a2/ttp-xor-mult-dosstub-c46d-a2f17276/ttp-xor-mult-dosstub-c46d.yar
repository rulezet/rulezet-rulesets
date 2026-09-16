rule TTP_XOR_MULT_DOSStub_c46d {
  strings:
    $key_c46d = { 90 05 [2] e4 1d [2] a3 1f [2] e4 0e [2] aa 02 [2] a6 08 [2] b1 03 [2] aa 4d [2] 97 }

  condition:
    any of them
}