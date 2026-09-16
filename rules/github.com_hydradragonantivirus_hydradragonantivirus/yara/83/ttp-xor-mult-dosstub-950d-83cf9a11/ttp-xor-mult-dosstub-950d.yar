rule TTP_XOR_MULT_DOSStub_950d {
  strings:
    $key_950d = { c1 65 [2] b5 7d [2] f2 7f [2] b5 6e [2] fb 62 [2] f7 68 [2] e0 63 [2] fb 2d [2] c6 }

  condition:
    any of them
}