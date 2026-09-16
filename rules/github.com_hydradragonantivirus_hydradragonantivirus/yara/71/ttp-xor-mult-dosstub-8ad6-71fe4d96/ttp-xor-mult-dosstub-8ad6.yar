rule TTP_XOR_MULT_DOSStub_8ad6 {
  strings:
    $key_8ad6 = { de be [2] aa a6 [2] ed a4 [2] aa b5 [2] e4 b9 [2] e8 b3 [2] ff b8 [2] e4 f6 [2] d9 }

  condition:
    any of them
}