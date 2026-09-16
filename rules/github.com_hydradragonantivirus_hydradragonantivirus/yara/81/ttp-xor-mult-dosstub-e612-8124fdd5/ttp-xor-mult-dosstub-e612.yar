rule TTP_XOR_MULT_DOSStub_e612 {
  strings:
    $key_e612 = { b2 7a [2] c6 62 [2] 81 60 [2] c6 71 [2] 88 7d [2] 84 77 [2] 93 7c [2] 88 32 [2] b5 }

  condition:
    any of them
}