rule TTP_XOR_MULT_DOSStub_046b {
  strings:
    $key_046b = { 50 03 [2] 24 1b [2] 63 19 [2] 24 08 [2] 6a 04 [2] 66 0e [2] 71 05 [2] 6a 4b [2] 57 }

  condition:
    any of them
}