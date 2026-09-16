rule TTP_XOR_MULT_DOSStub_7f6b {
  strings:
    $key_7f6b = { 2b 03 [2] 5f 1b [2] 18 19 [2] 5f 08 [2] 11 04 [2] 1d 0e [2] 0a 05 [2] 11 4b [2] 2c }

  condition:
    any of them
}