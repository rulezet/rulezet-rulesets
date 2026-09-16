rule TTP_XOR_MULT_DOSStub_4fc5 {
  strings:
    $key_4fc5 = { 1b ad [2] 6f b5 [2] 28 b7 [2] 6f a6 [2] 21 aa [2] 2d a0 [2] 3a ab [2] 21 e5 [2] 1c }

  condition:
    any of them
}