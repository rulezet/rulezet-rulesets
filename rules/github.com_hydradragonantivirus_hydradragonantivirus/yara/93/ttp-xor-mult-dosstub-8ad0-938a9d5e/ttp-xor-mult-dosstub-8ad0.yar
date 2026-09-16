rule TTP_XOR_MULT_DOSStub_8ad0 {
  strings:
    $key_8ad0 = { de b8 [2] aa a0 [2] ed a2 [2] aa b3 [2] e4 bf [2] e8 b5 [2] ff be [2] e4 f0 [2] d9 }

  condition:
    any of them
}