rule TTP_XOR_MULT_DOSStub_d73b {
  strings:
    $key_d73b = { 83 53 [2] f7 4b [2] b0 49 [2] f7 58 [2] b9 54 [2] b5 5e [2] a2 55 [2] b9 1b [2] 84 }

  condition:
    any of them
}