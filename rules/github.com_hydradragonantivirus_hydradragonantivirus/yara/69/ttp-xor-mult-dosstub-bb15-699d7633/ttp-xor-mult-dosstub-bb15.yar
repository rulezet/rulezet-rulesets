rule TTP_XOR_MULT_DOSStub_bb15 {
  strings:
    $key_bb15 = { ef 7d [2] 9b 65 [2] dc 67 [2] 9b 76 [2] d5 7a [2] d9 70 [2] ce 7b [2] d5 35 [2] e8 }

  condition:
    any of them
}