rule TTP_XOR_MULT_DOSStub_fc00 {
  strings:
    $key_fc00 = { a8 68 [2] dc 70 [2] 9b 72 [2] dc 63 [2] 92 6f [2] 9e 65 [2] 89 6e [2] 92 20 [2] af }

  condition:
    any of them
}