rule TTP_XOR_MULT_DOSStub_92cd {
  strings:
    $key_92cd = { c6 a5 [2] b2 bd [2] f5 bf [2] b2 ae [2] fc a2 [2] f0 a8 [2] e7 a3 [2] fc ed [2] c1 }

  condition:
    any of them
}