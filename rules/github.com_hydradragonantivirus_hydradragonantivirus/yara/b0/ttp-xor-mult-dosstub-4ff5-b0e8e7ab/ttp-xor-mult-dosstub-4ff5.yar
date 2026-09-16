rule TTP_XOR_MULT_DOSStub_4ff5 {
  strings:
    $key_4ff5 = { 1b 9d [2] 6f 85 [2] 28 87 [2] 6f 96 [2] 21 9a [2] 2d 90 [2] 3a 9b [2] 21 d5 [2] 1c }

  condition:
    any of them
}