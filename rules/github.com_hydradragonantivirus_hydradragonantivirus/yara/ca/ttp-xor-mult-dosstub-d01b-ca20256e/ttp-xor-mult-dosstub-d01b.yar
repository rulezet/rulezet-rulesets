rule TTP_XOR_MULT_DOSStub_d01b {
  strings:
    $key_d01b = { 84 73 [2] f0 6b [2] b7 69 [2] f0 78 [2] be 74 [2] b2 7e [2] a5 75 [2] be 3b [2] 83 }

  condition:
    any of them
}