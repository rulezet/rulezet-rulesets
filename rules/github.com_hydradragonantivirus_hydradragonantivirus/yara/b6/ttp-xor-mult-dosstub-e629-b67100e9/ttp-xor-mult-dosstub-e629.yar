rule TTP_XOR_MULT_DOSStub_e629 {
  strings:
    $key_e629 = { b2 41 [2] c6 59 [2] 81 5b [2] c6 4a [2] 88 46 [2] 84 4c [2] 93 47 [2] 88 09 [2] b5 }

  condition:
    any of them
}