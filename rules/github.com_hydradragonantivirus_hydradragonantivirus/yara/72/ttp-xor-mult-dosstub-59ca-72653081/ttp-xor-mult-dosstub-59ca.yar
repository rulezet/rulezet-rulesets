rule TTP_XOR_MULT_DOSStub_59ca {
  strings:
    $key_59ca = { 0d a2 [2] 79 ba [2] 3e b8 [2] 79 a9 [2] 37 a5 [2] 3b af [2] 2c a4 [2] 37 ea [2] 0a }

  condition:
    any of them
}