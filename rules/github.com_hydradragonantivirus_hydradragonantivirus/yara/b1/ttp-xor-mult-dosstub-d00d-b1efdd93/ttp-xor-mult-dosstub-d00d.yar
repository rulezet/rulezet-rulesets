rule TTP_XOR_MULT_DOSStub_d00d {
  strings:
    $key_d00d = { 84 65 [2] f0 7d [2] b7 7f [2] f0 6e [2] be 62 [2] b2 68 [2] a5 63 [2] be 2d [2] 83 }

  condition:
    any of them
}