rule TTP_XOR_MULT_DOSStub_a6cd {
  strings:
    $key_a6cd = { f2 a5 [2] 86 bd [2] c1 bf [2] 86 ae [2] c8 a2 [2] c4 a8 [2] d3 a3 [2] c8 ed [2] f5 }

  condition:
    any of them
}