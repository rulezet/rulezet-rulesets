rule TTP_XOR_MULT_DOSStub_d524 {
  strings:
    $key_d524 = { 81 4c [2] f5 54 [2] b2 56 [2] f5 47 [2] bb 4b [2] b7 41 [2] a0 4a [2] bb 04 [2] 86 }

  condition:
    any of them
}