rule TTP_XOR_MULT_DOSStub_fce3 {
  strings:
    $key_fce3 = { a8 8b [2] dc 93 [2] 9b 91 [2] dc 80 [2] 92 8c [2] 9e 86 [2] 89 8d [2] 92 c3 [2] af }

  condition:
    any of them
}