rule TTP_XOR_MULT_DOSStub_b2cd {
  strings:
    $key_b2cd = { e6 a5 [2] 92 bd [2] d5 bf [2] 92 ae [2] dc a2 [2] d0 a8 [2] c7 a3 [2] dc ed [2] e1 }

  condition:
    any of them
}