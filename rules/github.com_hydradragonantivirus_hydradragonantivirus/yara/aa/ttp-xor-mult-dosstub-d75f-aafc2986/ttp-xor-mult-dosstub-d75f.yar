rule TTP_XOR_MULT_DOSStub_d75f {
  strings:
    $key_d75f = { 83 37 [2] f7 2f [2] b0 2d [2] f7 3c [2] b9 30 [2] b5 3a [2] a2 31 [2] b9 7f [2] 84 }

  condition:
    any of them
}