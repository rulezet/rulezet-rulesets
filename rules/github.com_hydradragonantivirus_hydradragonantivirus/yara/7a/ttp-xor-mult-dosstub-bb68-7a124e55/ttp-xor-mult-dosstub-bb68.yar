rule TTP_XOR_MULT_DOSStub_bb68 {
  strings:
    $key_bb68 = { ef 00 [2] 9b 18 [2] dc 1a [2] 9b 0b [2] d5 07 [2] d9 0d [2] ce 06 [2] d5 48 [2] e8 }

  condition:
    any of them
}