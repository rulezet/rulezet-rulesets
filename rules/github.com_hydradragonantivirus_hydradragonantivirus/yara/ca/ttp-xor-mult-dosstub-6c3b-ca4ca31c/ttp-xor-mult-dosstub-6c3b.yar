rule TTP_XOR_MULT_DOSStub_6c3b {
  strings:
    $key_6c3b = { 38 53 [2] 4c 4b [2] 0b 49 [2] 4c 58 [2] 02 54 [2] 0e 5e [2] 19 55 [2] 02 1b [2] 3f }

  condition:
    any of them
}