rule TTP_XOR_MULT_DOSStub_c266 {
  strings:
    $key_c266 = { 96 0e [2] e2 16 [2] a5 14 [2] e2 05 [2] ac 09 [2] a0 03 [2] b7 08 [2] ac 46 [2] 91 }

  condition:
    any of them
}