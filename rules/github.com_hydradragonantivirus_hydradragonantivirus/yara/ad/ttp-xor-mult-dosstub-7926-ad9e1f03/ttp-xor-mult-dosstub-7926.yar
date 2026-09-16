rule TTP_XOR_MULT_DOSStub_7926 {
  strings:
    $key_7926 = { 2d 4e [2] 59 56 [2] 1e 54 [2] 59 45 [2] 17 49 [2] 1b 43 [2] 0c 48 [2] 17 06 [2] 2a }

  condition:
    any of them
}