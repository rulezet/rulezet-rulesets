rule TTP_XOR_MULT_DOSStub_d77d {
  strings:
    $key_d77d = { 83 15 [2] f7 0d [2] b0 0f [2] f7 1e [2] b9 12 [2] b5 18 [2] a2 13 [2] b9 5d [2] 84 }

  condition:
    any of them
}