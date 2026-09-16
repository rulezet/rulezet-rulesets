rule TTP_XOR_MULT_DOSStub_3bf0 {
  strings:
    $key_3bf0 = { 6f 98 [2] 1b 80 [2] 5c 82 [2] 1b 93 [2] 55 9f [2] 59 95 [2] 4e 9e [2] 55 d0 [2] 68 }

  condition:
    any of them
}