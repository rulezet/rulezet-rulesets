rule TTP_XOR_MULT_DOSStub_7976 {
  strings:
    $key_7976 = { 2d 1e [2] 59 06 [2] 1e 04 [2] 59 15 [2] 17 19 [2] 1b 13 [2] 0c 18 [2] 17 56 [2] 2a }

  condition:
    any of them
}