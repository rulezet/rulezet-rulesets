rule TTP_XOR_MULT_DOSStub_d02d {
  strings:
    $key_d02d = { 84 45 [2] f0 5d [2] b7 5f [2] f0 4e [2] be 42 [2] b2 48 [2] a5 43 [2] be 0d [2] 83 }

  condition:
    any of them
}