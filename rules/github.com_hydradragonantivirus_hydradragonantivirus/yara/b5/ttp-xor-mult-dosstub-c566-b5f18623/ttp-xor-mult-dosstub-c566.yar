rule TTP_XOR_MULT_DOSStub_c566 {
  strings:
    $key_c566 = { 91 0e [2] e5 16 [2] a2 14 [2] e5 05 [2] ab 09 [2] a7 03 [2] b0 08 [2] ab 46 [2] 96 }

  condition:
    any of them
}