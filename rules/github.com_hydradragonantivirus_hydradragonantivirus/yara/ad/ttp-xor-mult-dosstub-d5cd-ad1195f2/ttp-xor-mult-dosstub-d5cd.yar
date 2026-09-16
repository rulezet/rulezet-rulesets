rule TTP_XOR_MULT_DOSStub_d5cd {
  strings:
    $key_d5cd = { 81 a5 [2] f5 bd [2] b2 bf [2] f5 ae [2] bb a2 [2] b7 a8 [2] a0 a3 [2] bb ed [2] 86 }

  condition:
    any of them
}