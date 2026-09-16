rule TTP_XOR_MULT_DOSStub_d0ed {
  strings:
    $key_d0ed = { 84 85 [2] f0 9d [2] b7 9f [2] f0 8e [2] be 82 [2] b2 88 [2] a5 83 [2] be cd [2] 83 }

  condition:
    any of them
}