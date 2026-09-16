rule TTP_XOR_MULT_DOSStub_949a {
  strings:
    $key_949a = { c0 f2 [2] b4 ea [2] f3 e8 [2] b4 f9 [2] fa f5 [2] f6 ff [2] e1 f4 [2] fa ba [2] c7 }

  condition:
    any of them
}