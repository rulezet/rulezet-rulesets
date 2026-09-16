rule TTP_XOR_MULT_DOSStub_d07d {
  strings:
    $key_d07d = { 84 15 [2] f0 0d [2] b7 0f [2] f0 1e [2] be 12 [2] b2 18 [2] a5 13 [2] be 5d [2] 83 }

  condition:
    any of them
}