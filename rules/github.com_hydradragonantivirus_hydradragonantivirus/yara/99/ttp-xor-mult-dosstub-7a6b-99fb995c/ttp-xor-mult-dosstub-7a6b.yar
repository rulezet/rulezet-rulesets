rule TTP_XOR_MULT_DOSStub_7a6b {
  strings:
    $key_7a6b = { 2e 03 [2] 5a 1b [2] 1d 19 [2] 5a 08 [2] 14 04 [2] 18 0e [2] 0f 05 [2] 14 4b [2] 29 }

  condition:
    any of them
}