rule TTP_XOR_MULT_DOSStub_a5cd {
  strings:
    $key_a5cd = { f1 a5 [2] 85 bd [2] c2 bf [2] 85 ae [2] cb a2 [2] c7 a8 [2] d0 a3 [2] cb ed [2] f6 }

  condition:
    any of them
}