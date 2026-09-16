rule TTP_XOR_MULT_DOSStub_d043 {
  strings:
    $key_d043 = { 84 2b [2] f0 33 [2] b7 31 [2] f0 20 [2] be 2c [2] b2 26 [2] a5 2d [2] be 63 [2] 83 }

  condition:
    any of them
}