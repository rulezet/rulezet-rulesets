rule TTP_XOR_MULT_DOSStub_d762 {
  strings:
    $key_d762 = { 83 0a [2] f7 12 [2] b0 10 [2] f7 01 [2] b9 0d [2] b5 07 [2] a2 0c [2] b9 42 [2] 84 }

  condition:
    any of them
}