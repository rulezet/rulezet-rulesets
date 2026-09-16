rule TTP_XOR_MULT_DOSStub_c466 {
  strings:
    $key_c466 = { 90 0e [2] e4 16 [2] a3 14 [2] e4 05 [2] aa 09 [2] a6 03 [2] b1 08 [2] aa 46 [2] 97 }

  condition:
    any of them
}