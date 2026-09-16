rule TTP_XOR_MULT_DOSStub_79e1 {
  strings:
    $key_79e1 = { 2d 89 [2] 59 91 [2] 1e 93 [2] 59 82 [2] 17 8e [2] 1b 84 [2] 0c 8f [2] 17 c1 [2] 2a }

  condition:
    any of them
}