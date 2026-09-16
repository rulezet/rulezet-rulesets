rule TTP_XOR_MULT_DOSStub_fdd2 {
  strings:
    $key_fdd2 = { a9 ba [2] dd a2 [2] 9a a0 [2] dd b1 [2] 93 bd [2] 9f b7 [2] 88 bc [2] 93 f2 [2] ae }

  condition:
    any of them
}