rule TTP_XOR_MULT_DOSStub_576b {
  strings:
    $key_576b = { 03 03 [2] 77 1b [2] 30 19 [2] 77 08 [2] 39 04 [2] 35 0e [2] 22 05 [2] 39 4b [2] 04 }

  condition:
    any of them
}