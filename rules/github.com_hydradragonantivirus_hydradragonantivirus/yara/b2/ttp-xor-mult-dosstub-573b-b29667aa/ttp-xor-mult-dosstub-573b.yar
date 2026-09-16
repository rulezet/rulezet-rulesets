rule TTP_XOR_MULT_DOSStub_573b {
  strings:
    $key_573b = { 03 53 [2] 77 4b [2] 30 49 [2] 77 58 [2] 39 54 [2] 35 5e [2] 22 55 [2] 39 1b [2] 04 }

  condition:
    any of them
}