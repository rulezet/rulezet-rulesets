rule TTP_XOR_MULT_DOSStub_fce0 {
  strings:
    $key_fce0 = { a8 88 [2] dc 90 [2] 9b 92 [2] dc 83 [2] 92 8f [2] 9e 85 [2] 89 8e [2] 92 c0 [2] af }

  condition:
    any of them
}