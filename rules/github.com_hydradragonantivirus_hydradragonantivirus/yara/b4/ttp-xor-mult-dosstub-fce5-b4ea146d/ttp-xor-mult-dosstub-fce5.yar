rule TTP_XOR_MULT_DOSStub_fce5 {
  strings:
    $key_fce5 = { a8 8d [2] dc 95 [2] 9b 97 [2] dc 86 [2] 92 8a [2] 9e 80 [2] 89 8b [2] 92 c5 [2] af }

  condition:
    any of them
}