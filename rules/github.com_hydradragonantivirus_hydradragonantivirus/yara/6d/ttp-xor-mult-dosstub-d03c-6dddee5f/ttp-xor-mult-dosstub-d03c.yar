rule TTP_XOR_MULT_DOSStub_d03c {
  strings:
    $key_d03c = { 84 54 [2] f0 4c [2] b7 4e [2] f0 5f [2] be 53 [2] b2 59 [2] a5 52 [2] be 1c [2] 83 }

  condition:
    any of them
}