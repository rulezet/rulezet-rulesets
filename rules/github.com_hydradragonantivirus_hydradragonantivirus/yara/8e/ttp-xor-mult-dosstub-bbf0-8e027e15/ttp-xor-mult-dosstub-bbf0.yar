rule TTP_XOR_MULT_DOSStub_bbf0 {
  strings:
    $key_bbf0 = { ef 98 [2] 9b 80 [2] dc 82 [2] 9b 93 [2] d5 9f [2] d9 95 [2] ce 9e [2] d5 d0 [2] e8 }

  condition:
    any of them
}