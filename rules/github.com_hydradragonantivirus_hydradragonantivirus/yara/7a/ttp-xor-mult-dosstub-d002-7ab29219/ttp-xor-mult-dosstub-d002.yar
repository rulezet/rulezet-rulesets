rule TTP_XOR_MULT_DOSStub_d002 {
  strings:
    $key_d002 = { 84 6a [2] f0 72 [2] b7 70 [2] f0 61 [2] be 6d [2] b2 67 [2] a5 6c [2] be 22 [2] 83 }

  condition:
    any of them
}