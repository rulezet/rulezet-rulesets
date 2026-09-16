rule TTP_XOR_MULT_DOSStub_786b {
  strings:
    $key_786b = { 2c 03 [2] 58 1b [2] 1f 19 [2] 58 08 [2] 16 04 [2] 1a 0e [2] 0d 05 [2] 16 4b [2] 2b }

  condition:
    any of them
}