rule TTP_XOR_MULT_DOSStub_d066 {
  strings:
    $key_d066 = { 84 0e [2] f0 16 [2] b7 14 [2] f0 05 [2] be 09 [2] b2 03 [2] a5 08 [2] be 46 [2] 83 }

  condition:
    any of them
}