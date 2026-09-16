rule TTP_XOR_MULT_DOSStub_bb76 {
  strings:
    $key_bb76 = { ef 1e [2] 9b 06 [2] dc 04 [2] 9b 15 [2] d5 19 [2] d9 13 [2] ce 18 [2] d5 56 [2] e8 }

  condition:
    any of them
}