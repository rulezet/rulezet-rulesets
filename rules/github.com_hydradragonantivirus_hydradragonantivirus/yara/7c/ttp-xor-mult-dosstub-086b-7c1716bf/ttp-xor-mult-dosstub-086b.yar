rule TTP_XOR_MULT_DOSStub_086b {
  strings:
    $key_086b = { 5c 03 [2] 28 1b [2] 6f 19 [2] 28 08 [2] 66 04 [2] 6a 0e [2] 7d 05 [2] 66 4b [2] 5b }

  condition:
    any of them
}