rule TTP_XOR_MULT_DOSStub_b6cd {
  strings:
    $key_b6cd = { e2 a5 [2] 96 bd [2] d1 bf [2] 96 ae [2] d8 a2 [2] d4 a8 [2] c3 a3 [2] d8 ed [2] e5 }

  condition:
    any of them
}