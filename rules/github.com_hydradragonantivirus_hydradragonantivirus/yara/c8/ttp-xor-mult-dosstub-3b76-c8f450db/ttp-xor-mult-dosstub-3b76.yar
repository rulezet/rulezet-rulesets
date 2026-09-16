rule TTP_XOR_MULT_DOSStub_3b76 {
  strings:
    $key_3b76 = { 6f 1e [2] 1b 06 [2] 5c 04 [2] 1b 15 [2] 55 19 [2] 59 13 [2] 4e 18 [2] 55 56 [2] 68 }

  condition:
    any of them
}