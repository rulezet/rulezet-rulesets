rule TTP_XOR_MULT_DOSStub_4de1 {
  strings:
    $key_4de1 = { 19 89 [2] 6d 91 [2] 2a 93 [2] 6d 82 [2] 23 8e [2] 2f 84 [2] 38 8f [2] 23 c1 [2] 1e }

  condition:
    any of them
}