rule TTP_XOR_MULT_DOSStub_85cd {
  strings:
    $key_85cd = { d1 a5 [2] a5 bd [2] e2 bf [2] a5 ae [2] eb a2 [2] e7 a8 [2] f0 a3 [2] eb ed [2] d6 }

  condition:
    any of them
}