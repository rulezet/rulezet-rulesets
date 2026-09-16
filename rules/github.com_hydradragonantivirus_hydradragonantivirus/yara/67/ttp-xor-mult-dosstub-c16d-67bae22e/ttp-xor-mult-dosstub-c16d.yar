rule TTP_XOR_MULT_DOSStub_c16d {
  strings:
    $key_c16d = { 95 05 [2] e1 1d [2] a6 1f [2] e1 0e [2] af 02 [2] a3 08 [2] b4 03 [2] af 4d [2] 92 }

  condition:
    any of them
}