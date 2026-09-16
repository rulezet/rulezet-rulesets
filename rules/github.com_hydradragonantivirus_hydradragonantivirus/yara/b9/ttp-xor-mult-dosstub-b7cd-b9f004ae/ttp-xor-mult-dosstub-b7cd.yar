rule TTP_XOR_MULT_DOSStub_b7cd {
  strings:
    $key_b7cd = { e3 a5 [2] 97 bd [2] d0 bf [2] 97 ae [2] d9 a2 [2] d5 a8 [2] c2 a3 [2] d9 ed [2] e4 }

  condition:
    any of them
}