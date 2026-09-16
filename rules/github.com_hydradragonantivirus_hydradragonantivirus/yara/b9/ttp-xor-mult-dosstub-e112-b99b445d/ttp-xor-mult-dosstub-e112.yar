rule TTP_XOR_MULT_DOSStub_e112 {
  strings:
    $key_e112 = { b5 7a [2] c1 62 [2] 86 60 [2] c1 71 [2] 8f 7d [2] 83 77 [2] 94 7c [2] 8f 32 [2] b2 }

  condition:
    any of them
}