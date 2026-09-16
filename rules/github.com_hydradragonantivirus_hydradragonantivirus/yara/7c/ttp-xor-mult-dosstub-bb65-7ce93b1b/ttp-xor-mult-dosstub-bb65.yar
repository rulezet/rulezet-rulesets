rule TTP_XOR_MULT_DOSStub_bb65 {
  strings:
    $key_bb65 = { ef 0d [2] 9b 15 [2] dc 17 [2] 9b 06 [2] d5 0a [2] d9 00 [2] ce 0b [2] d5 45 [2] e8 }

  condition:
    any of them
}