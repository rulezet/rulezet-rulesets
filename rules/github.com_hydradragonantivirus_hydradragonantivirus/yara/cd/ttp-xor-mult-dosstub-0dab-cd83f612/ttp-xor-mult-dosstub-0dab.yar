rule TTP_XOR_MULT_DOSStub_0dab {
  strings:
    $key_0dab = { 59 c3 [2] 2d db [2] 6a d9 [2] 2d c8 [2] 63 c4 [2] 6f ce [2] 78 c5 [2] 63 8b [2] 5e }

  condition:
    any of them
}