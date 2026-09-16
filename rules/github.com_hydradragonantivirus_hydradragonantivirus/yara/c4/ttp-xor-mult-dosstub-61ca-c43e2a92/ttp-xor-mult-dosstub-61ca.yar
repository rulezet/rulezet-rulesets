rule TTP_XOR_MULT_DOSStub_61ca {
  strings:
    $key_61ca = { 35 a2 [2] 41 ba [2] 06 b8 [2] 41 a9 [2] 0f a5 [2] 03 af [2] 14 a4 [2] 0f ea [2] 32 }

  condition:
    any of them
}