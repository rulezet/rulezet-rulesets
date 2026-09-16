rule TTP_XOR_MULT_DOSStub_d4e0 {
  strings:
    $key_d4e0 = { 80 88 [2] f4 90 [2] b3 92 [2] f4 83 [2] ba 8f [2] b6 85 [2] a1 8e [2] ba c0 [2] 87 }

  condition:
    any of them
}