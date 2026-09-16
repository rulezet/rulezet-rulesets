rule TTP_XOR_MULT_DOSStub_d70d {
  strings:
    $key_d70d = { 83 65 [2] f7 7d [2] b0 7f [2] f7 6e [2] b9 62 [2] b5 68 [2] a2 63 [2] b9 2d [2] 84 }

  condition:
    any of them
}