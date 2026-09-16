rule TTP_XOR_MULT_DOSStub_bb41 {
  strings:
    $key_bb41 = { ef 29 [2] 9b 31 [2] dc 33 [2] 9b 22 [2] d5 2e [2] d9 24 [2] ce 2f [2] d5 61 [2] e8 }

  condition:
    any of them
}