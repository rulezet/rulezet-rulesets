rule TTP_XOR_MULT_DOSStub_ffd6 {
  strings:
    $key_ffd6 = { ab be [2] df a6 [2] 98 a4 [2] df b5 [2] 91 b9 [2] 9d b3 [2] 8a b8 [2] 91 f6 [2] ac }

  condition:
    any of them
}