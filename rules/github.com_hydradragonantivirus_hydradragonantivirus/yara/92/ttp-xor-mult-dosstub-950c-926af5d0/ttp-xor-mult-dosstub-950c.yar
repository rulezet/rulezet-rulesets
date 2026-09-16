rule TTP_XOR_MULT_DOSStub_950c {
  strings:
    $key_950c = { c1 64 [2] b5 7c [2] f2 7e [2] b5 6f [2] fb 63 [2] f7 69 [2] e0 62 [2] fb 2c [2] c6 }

  condition:
    any of them
}