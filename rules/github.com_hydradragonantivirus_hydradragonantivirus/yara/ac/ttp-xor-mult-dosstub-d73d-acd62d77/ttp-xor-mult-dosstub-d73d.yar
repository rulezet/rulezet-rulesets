rule TTP_XOR_MULT_DOSStub_d73d {
  strings:
    $key_d73d = { 83 55 [2] f7 4d [2] b0 4f [2] f7 5e [2] b9 52 [2] b5 58 [2] a2 53 [2] b9 1d [2] 84 }

  condition:
    any of them
}