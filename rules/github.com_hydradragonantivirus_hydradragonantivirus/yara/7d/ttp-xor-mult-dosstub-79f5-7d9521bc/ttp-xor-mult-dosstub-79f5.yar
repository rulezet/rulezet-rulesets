rule TTP_XOR_MULT_DOSStub_79f5 {
  strings:
    $key_79f5 = { 2d 9d [2] 59 85 [2] 1e 87 [2] 59 96 [2] 17 9a [2] 1b 90 [2] 0c 9b [2] 17 d5 [2] 2a }

  condition:
    any of them
}