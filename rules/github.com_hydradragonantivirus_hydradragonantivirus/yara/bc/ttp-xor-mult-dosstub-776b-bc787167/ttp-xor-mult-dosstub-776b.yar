rule TTP_XOR_MULT_DOSStub_776b {
  strings:
    $key_776b = { 23 03 [2] 57 1b [2] 10 19 [2] 57 08 [2] 19 04 [2] 15 0e [2] 02 05 [2] 19 4b [2] 24 }

  condition:
    any of them
}