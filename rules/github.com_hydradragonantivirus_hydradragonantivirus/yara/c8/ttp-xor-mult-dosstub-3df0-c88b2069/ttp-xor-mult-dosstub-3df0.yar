rule TTP_XOR_MULT_DOSStub_3df0 {
  strings:
    $key_3df0 = { 69 98 [2] 1d 80 [2] 5a 82 [2] 1d 93 [2] 53 9f [2] 5f 95 [2] 48 9e [2] 53 d0 [2] 6e }

  condition:
    any of them
}