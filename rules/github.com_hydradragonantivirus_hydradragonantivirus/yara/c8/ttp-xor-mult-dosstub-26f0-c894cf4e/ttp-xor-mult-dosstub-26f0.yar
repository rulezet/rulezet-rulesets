rule TTP_XOR_MULT_DOSStub_26f0 {
  strings:
    $key_26f0 = { 72 98 [2] 06 80 [2] 41 82 [2] 06 93 [2] 48 9f [2] 44 95 [2] 53 9e [2] 48 d0 [2] 75 }

  condition:
    any of them
}