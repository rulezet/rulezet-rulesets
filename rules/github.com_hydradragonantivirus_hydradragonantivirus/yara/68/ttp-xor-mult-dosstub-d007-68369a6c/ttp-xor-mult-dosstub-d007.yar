rule TTP_XOR_MULT_DOSStub_d007 {
  strings:
    $key_d007 = { 84 6f [2] f0 77 [2] b7 75 [2] f0 64 [2] be 68 [2] b2 62 [2] a5 69 [2] be 27 [2] 83 }

  condition:
    any of them
}