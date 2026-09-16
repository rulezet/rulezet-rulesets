rule TTP_XOR_MULT_DOSStub_bb26 {
  strings:
    $key_bb26 = { ef 4e [2] 9b 56 [2] dc 54 [2] 9b 45 [2] d5 49 [2] d9 43 [2] ce 48 [2] d5 06 [2] e8 }

  condition:
    any of them
}