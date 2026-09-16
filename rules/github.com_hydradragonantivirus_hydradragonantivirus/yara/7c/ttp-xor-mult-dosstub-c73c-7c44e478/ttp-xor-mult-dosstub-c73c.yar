rule TTP_XOR_MULT_DOSStub_c73c {
  strings:
    $key_c73c = { 93 54 [2] e7 4c [2] a0 4e [2] e7 5f [2] a9 53 [2] a5 59 [2] b2 52 [2] a9 1c [2] 94 }

  condition:
    any of them
}