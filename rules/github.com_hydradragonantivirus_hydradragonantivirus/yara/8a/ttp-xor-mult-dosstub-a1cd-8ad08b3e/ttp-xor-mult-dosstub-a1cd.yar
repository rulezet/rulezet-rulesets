rule TTP_XOR_MULT_DOSStub_a1cd {
  strings:
    $key_a1cd = { f5 a5 [2] 81 bd [2] c6 bf [2] 81 ae [2] cf a2 [2] c3 a8 [2] d4 a3 [2] cf ed [2] f2 }

  condition:
    any of them
}