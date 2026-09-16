rule TTP_XOR_MULT_DOSStub_6dab {
  strings:
    $key_6dab = { 39 c3 [2] 4d db [2] 0a d9 [2] 4d c8 [2] 03 c4 [2] 0f ce [2] 18 c5 [2] 03 8b [2] 3e }

  condition:
    any of them
}