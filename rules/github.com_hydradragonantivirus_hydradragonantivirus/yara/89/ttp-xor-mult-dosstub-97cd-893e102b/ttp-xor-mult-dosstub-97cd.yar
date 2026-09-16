rule TTP_XOR_MULT_DOSStub_97cd {
  strings:
    $key_97cd = { c3 a5 [2] b7 bd [2] f0 bf [2] b7 ae [2] f9 a2 [2] f5 a8 [2] e2 a3 [2] f9 ed [2] c4 }

  condition:
    any of them
}