rule TTP_XOR_MULT_DOSStub_7bf0 {
  strings:
    $key_7bf0 = { 2f 98 [2] 5b 80 [2] 1c 82 [2] 5b 93 [2] 15 9f [2] 19 95 [2] 0e 9e [2] 15 d0 [2] 28 }

  condition:
    any of them
}