rule TTP_XOR_MULT_DOSStub_e135 {
  strings:
    $key_e135 = { b5 5d [2] c1 45 [2] 86 47 [2] c1 56 [2] 8f 5a [2] 83 50 [2] 94 5b [2] 8f 15 [2] b2 }

  condition:
    any of them
}