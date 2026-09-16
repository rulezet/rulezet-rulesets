rule TTP_XOR_MULT_DOSStub_d52f {
  strings:
    $key_d52f = { 81 47 [2] f5 5f [2] b2 5d [2] f5 4c [2] bb 40 [2] b7 4a [2] a0 41 [2] bb 0f [2] 86 }

  condition:
    any of them
}