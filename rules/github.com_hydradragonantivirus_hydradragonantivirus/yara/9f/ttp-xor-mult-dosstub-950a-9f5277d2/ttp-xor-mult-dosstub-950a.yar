rule TTP_XOR_MULT_DOSStub_950a {
  strings:
    $key_950a = { c1 62 [2] b5 7a [2] f2 78 [2] b5 69 [2] fb 65 [2] f7 6f [2] e0 64 [2] fb 2a [2] c6 }

  condition:
    any of them
}