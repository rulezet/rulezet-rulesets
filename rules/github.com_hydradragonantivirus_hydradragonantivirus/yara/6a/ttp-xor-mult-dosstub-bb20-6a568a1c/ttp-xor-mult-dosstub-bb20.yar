rule TTP_XOR_MULT_DOSStub_bb20 {
  strings:
    $key_bb20 = { ef 48 [2] 9b 50 [2] dc 52 [2] 9b 43 [2] d5 4f [2] d9 45 [2] ce 4e [2] d5 00 [2] e8 }

  condition:
    any of them
}