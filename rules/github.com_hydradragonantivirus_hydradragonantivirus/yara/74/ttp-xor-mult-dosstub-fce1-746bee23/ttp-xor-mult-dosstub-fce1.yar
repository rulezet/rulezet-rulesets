rule TTP_XOR_MULT_DOSStub_fce1 {
  strings:
    $key_fce1 = { a8 89 [2] dc 91 [2] 9b 93 [2] dc 82 [2] 92 8e [2] 9e 84 [2] 89 8f [2] 92 c1 [2] af }

  condition:
    any of them
}