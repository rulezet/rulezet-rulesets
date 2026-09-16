rule TTP_XOR_MULT_DOSStub_d027 {
  strings:
    $key_d027 = { 84 4f [2] f0 57 [2] b7 55 [2] f0 44 [2] be 48 [2] b2 42 [2] a5 49 [2] be 07 [2] 83 }

  condition:
    any of them
}