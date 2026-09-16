rule TTP_XOR_MULT_DOSStub_fce8 {
  strings:
    $key_fce8 = { a8 80 [2] dc 98 [2] 9b 9a [2] dc 8b [2] 92 87 [2] 9e 8d [2] 89 86 [2] 92 c8 [2] af }

  condition:
    any of them
}