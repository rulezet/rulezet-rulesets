rule TTP_XOR_MULT_DOSStub_e412 {
  strings:
    $key_e412 = { b0 7a [2] c4 62 [2] 83 60 [2] c4 71 [2] 8a 7d [2] 86 77 [2] 91 7c [2] 8a 32 [2] b7 }

  condition:
    any of them
}