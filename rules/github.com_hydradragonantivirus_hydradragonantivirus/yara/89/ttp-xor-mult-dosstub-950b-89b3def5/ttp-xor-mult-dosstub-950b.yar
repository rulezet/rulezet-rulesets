rule TTP_XOR_MULT_DOSStub_950b {
  strings:
    $key_950b = { c1 63 [2] b5 7b [2] f2 79 [2] b5 68 [2] fb 64 [2] f7 6e [2] e0 65 [2] fb 2b [2] c6 }

  condition:
    any of them
}