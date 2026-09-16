rule TTP_XOR_MULT_DOSStub_d02e {
  strings:
    $key_d02e = { 84 46 [2] f0 5e [2] b7 5c [2] f0 4d [2] be 41 [2] b2 4b [2] a5 40 [2] be 0e [2] 83 }

  condition:
    any of them
}