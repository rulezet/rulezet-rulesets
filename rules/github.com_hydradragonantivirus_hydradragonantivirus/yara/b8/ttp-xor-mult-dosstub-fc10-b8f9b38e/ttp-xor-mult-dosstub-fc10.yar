rule TTP_XOR_MULT_DOSStub_fc10 {
  strings:
    $key_fc10 = { a8 78 [2] dc 60 [2] 9b 62 [2] dc 73 [2] 92 7f [2] 9e 75 [2] 89 7e [2] 92 30 [2] af }

  condition:
    any of them
}