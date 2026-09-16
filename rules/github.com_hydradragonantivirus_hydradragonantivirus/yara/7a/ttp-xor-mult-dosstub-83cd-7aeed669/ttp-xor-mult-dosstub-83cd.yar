rule TTP_XOR_MULT_DOSStub_83cd {
  strings:
    $key_83cd = { d7 a5 [2] a3 bd [2] e4 bf [2] a3 ae [2] ed a2 [2] e1 a8 [2] f6 a3 [2] ed ed [2] d0 }

  condition:
    any of them
}