rule TTP_XOR_MULT_DOSStub_596b {
  strings:
    $key_596b = { 0d 03 [2] 79 1b [2] 3e 19 [2] 79 08 [2] 37 04 [2] 3b 0e [2] 2c 05 [2] 37 4b [2] 0a }

  condition:
    any of them
}