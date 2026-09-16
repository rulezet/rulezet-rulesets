rule TTP_XOR_MULT_DOSStub_fc55 {
  strings:
    $key_fc55 = { a8 3d [2] dc 25 [2] 9b 27 [2] dc 36 [2] 92 3a [2] 9e 30 [2] 89 3b [2] 92 75 [2] af }

  condition:
    any of them
}