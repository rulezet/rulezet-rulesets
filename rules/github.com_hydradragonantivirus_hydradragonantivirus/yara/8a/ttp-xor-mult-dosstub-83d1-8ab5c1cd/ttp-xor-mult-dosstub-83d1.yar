rule TTP_XOR_MULT_DOSStub_83d1 {
  strings:
    $key_83d1 = { d7 b9 [2] a3 a1 [2] e4 a3 [2] a3 b2 [2] ed be [2] e1 b4 [2] f6 bf [2] ed f1 [2] d0 }

  condition:
    any of them
}