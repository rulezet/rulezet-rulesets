rule TTP_XOR_MULT_DOSStub_2ccb {
  strings:
    $key_2ccb = { 78 a3 [2] 0c bb [2] 4b b9 [2] 0c a8 [2] 42 a4 [2] 4e ae [2] 59 a5 [2] 42 eb [2] 7f }

  condition:
    any of them
}