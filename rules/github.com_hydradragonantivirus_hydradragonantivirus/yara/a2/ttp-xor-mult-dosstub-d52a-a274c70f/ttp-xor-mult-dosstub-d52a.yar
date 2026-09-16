rule TTP_XOR_MULT_DOSStub_d52a {
  strings:
    $key_d52a = { 81 42 [2] f5 5a [2] b2 58 [2] f5 49 [2] bb 45 [2] b7 4f [2] a0 44 [2] bb 0a [2] 86 }

  condition:
    any of them
}