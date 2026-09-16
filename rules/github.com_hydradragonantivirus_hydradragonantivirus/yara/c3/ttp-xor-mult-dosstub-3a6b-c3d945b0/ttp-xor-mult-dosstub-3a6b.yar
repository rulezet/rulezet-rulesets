rule TTP_XOR_MULT_DOSStub_3a6b {
  strings:
    $key_3a6b = { 6e 03 [2] 1a 1b [2] 5d 19 [2] 1a 08 [2] 54 04 [2] 58 0e [2] 4f 05 [2] 54 4b [2] 69 }

  condition:
    any of them
}