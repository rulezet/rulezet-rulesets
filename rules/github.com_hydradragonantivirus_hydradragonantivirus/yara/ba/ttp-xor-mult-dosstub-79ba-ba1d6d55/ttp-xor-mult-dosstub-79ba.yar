rule TTP_XOR_MULT_DOSStub_79ba {
  strings:
    $key_79ba = { 2d d2 [2] 59 ca [2] 1e c8 [2] 59 d9 [2] 17 d5 [2] 1b df [2] 0c d4 [2] 17 9a [2] 2a }

  condition:
    any of them
}