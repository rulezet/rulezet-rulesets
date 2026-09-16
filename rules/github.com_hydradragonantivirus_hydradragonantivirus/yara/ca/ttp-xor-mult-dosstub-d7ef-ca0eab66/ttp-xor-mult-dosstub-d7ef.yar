rule TTP_XOR_MULT_DOSStub_d7ef {
  strings:
    $key_d7ef = { 83 87 [2] f7 9f [2] b0 9d [2] f7 8c [2] b9 80 [2] b5 8a [2] a2 81 [2] b9 cf [2] 84 }

  condition:
    any of them
}