rule TTP_XOR_MULT_DOSStub_c660 {
  strings:
    $key_c660 = { 92 08 [2] e6 10 [2] a1 12 [2] e6 03 [2] a8 0f [2] a4 05 [2] b3 0e [2] a8 40 [2] 95 }

  condition:
    any of them
}