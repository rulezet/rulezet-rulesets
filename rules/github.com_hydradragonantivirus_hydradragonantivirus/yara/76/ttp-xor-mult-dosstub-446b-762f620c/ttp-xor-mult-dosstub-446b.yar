rule TTP_XOR_MULT_DOSStub_446b {
  strings:
    $key_446b = { 10 03 [2] 64 1b [2] 23 19 [2] 64 08 [2] 2a 04 [2] 26 0e [2] 31 05 [2] 2a 4b [2] 17 }

  condition:
    any of them
}