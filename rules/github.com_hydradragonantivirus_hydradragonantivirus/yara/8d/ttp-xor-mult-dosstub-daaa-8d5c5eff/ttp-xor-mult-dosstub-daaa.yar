rule TTP_XOR_MULT_DOSStub_daaa {
  strings:
    $key_daaa = { 8e c2 [2] fa da [2] bd d8 [2] fa c9 [2] b4 c5 [2] b8 cf [2] af c4 [2] b4 8a [2] 89 }

  condition:
    any of them
}