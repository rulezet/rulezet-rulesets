rule TTP_XOR_MULT_DOSStub_156b {
  strings:
    $key_156b = { 41 03 [2] 35 1b [2] 72 19 [2] 35 08 [2] 7b 04 [2] 77 0e [2] 60 05 [2] 7b 4b [2] 46 }

  condition:
    any of them
}