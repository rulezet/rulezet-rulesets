rule TTP_XOR_MULT_DOSStub_bb31 {
  strings:
    $key_bb31 = { ef 59 [2] 9b 41 [2] dc 43 [2] 9b 52 [2] d5 5e [2] d9 54 [2] ce 5f [2] d5 11 [2] e8 }

  condition:
    any of them
}