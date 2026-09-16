rule TTP_XOR_MULT_DOSStub_e175 {
  strings:
    $key_e175 = { b5 1d [2] c1 05 [2] 86 07 [2] c1 16 [2] 8f 1a [2] 83 10 [2] 94 1b [2] 8f 55 [2] b2 }

  condition:
    any of them
}