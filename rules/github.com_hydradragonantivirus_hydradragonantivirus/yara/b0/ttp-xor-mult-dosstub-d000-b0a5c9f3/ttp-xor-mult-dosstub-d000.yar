rule TTP_XOR_MULT_DOSStub_d000 {
  strings:
    $key_d000 = { 84 68 [2] f0 70 [2] b7 72 [2] f0 63 [2] be 6f [2] b2 65 [2] a5 6e [2] be 20 [2] 83 }

  condition:
    any of them
}