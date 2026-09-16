rule TTP_XOR_MULT_DOSStub_d064 {
  strings:
    $key_d064 = { 84 0c [2] f0 14 [2] b7 16 [2] f0 07 [2] be 0b [2] b2 01 [2] a5 0a [2] be 44 [2] 83 }

  condition:
    any of them
}