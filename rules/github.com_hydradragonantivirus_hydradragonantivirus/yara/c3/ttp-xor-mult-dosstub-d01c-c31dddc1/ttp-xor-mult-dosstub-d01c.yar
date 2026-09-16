rule TTP_XOR_MULT_DOSStub_d01c {
  strings:
    $key_d01c = { 84 74 [2] f0 6c [2] b7 6e [2] f0 7f [2] be 73 [2] b2 79 [2] a5 72 [2] be 3c [2] 83 }

  condition:
    any of them
}