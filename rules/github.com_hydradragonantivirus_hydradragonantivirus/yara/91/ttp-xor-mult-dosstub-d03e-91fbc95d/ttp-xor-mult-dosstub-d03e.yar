rule TTP_XOR_MULT_DOSStub_d03e {
  strings:
    $key_d03e = { 84 56 [2] f0 4e [2] b7 4c [2] f0 5d [2] be 51 [2] b2 5b [2] a5 50 [2] be 1e [2] 83 }

  condition:
    any of them
}