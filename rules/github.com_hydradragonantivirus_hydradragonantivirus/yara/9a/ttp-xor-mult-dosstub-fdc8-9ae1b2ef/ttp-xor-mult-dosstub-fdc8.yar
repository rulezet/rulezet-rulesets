rule TTP_XOR_MULT_DOSStub_fdc8 {
  strings:
    $key_fdc8 = { a9 a0 [2] dd b8 [2] 9a ba [2] dd ab [2] 93 a7 [2] 9f ad [2] 88 a6 [2] 93 e8 [2] ae }

  condition:
    any of them
}