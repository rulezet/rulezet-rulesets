rule TTP_XOR_MULT_DOSStub_9501 {
  strings:
    $key_9501 = { c1 69 [2] b5 71 [2] f2 73 [2] b5 62 [2] fb 6e [2] f7 64 [2] e0 6f [2] fb 21 [2] c6 }

  condition:
    any of them
}