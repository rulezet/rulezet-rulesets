rule TTP_XOR_MULT_DOSStub_706b {
  strings:
    $key_706b = { 24 03 [2] 50 1b [2] 17 19 [2] 50 08 [2] 1e 04 [2] 12 0e [2] 05 05 [2] 1e 4b [2] 23 }

  condition:
    any of them
}