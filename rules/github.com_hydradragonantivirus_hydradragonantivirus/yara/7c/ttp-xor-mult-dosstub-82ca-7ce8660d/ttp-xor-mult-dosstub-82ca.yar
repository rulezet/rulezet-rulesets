rule TTP_XOR_MULT_DOSStub_82ca {
  strings:
    $key_82ca = { d6 a2 [2] a2 ba [2] e5 b8 [2] a2 a9 [2] ec a5 [2] e0 af [2] f7 a4 [2] ec ea [2] d1 }

  condition:
    any of them
}