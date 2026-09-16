rule TTP_XOR_MULT_DOSStub_246b {
  strings:
    $key_246b = { 70 03 [2] 04 1b [2] 43 19 [2] 04 08 [2] 4a 04 [2] 46 0e [2] 51 05 [2] 4a 4b [2] 77 }

  condition:
    any of them
}