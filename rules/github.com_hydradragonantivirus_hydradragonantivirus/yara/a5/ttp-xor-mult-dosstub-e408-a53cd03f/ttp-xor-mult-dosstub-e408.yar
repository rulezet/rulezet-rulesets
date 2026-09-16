rule TTP_XOR_MULT_DOSStub_e408 {
  strings:
    $key_e408 = { b0 60 [2] c4 78 [2] 83 7a [2] c4 6b [2] 8a 67 [2] 86 6d [2] 91 66 [2] 8a 28 [2] b7 }

  condition:
    any of them
}