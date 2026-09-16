rule TTP_XOR_MULT_DOSStub_d011 {
  strings:
    $key_d011 = { 84 79 [2] f0 61 [2] b7 63 [2] f0 72 [2] be 7e [2] b2 74 [2] a5 7f [2] be 31 [2] 83 }

  condition:
    any of them
}