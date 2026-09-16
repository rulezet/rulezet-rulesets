rule TTP_XOR_MULT_DOSStub_676b {
  strings:
    $key_676b = { 33 03 [2] 47 1b [2] 00 19 [2] 47 08 [2] 09 04 [2] 05 0e [2] 12 05 [2] 09 4b [2] 34 }

  condition:
    any of them
}