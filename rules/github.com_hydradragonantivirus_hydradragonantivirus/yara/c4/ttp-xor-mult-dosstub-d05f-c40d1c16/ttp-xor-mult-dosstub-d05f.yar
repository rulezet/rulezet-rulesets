rule TTP_XOR_MULT_DOSStub_d05f {
  strings:
    $key_d05f = { 84 37 [2] f0 2f [2] b7 2d [2] f0 3c [2] be 30 [2] b2 3a [2] a5 31 [2] be 7f [2] 83 }

  condition:
    any of them
}