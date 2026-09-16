rule TTP_XOR_MULT_DOSStub_106b {
  strings:
    $key_106b = { 44 03 [2] 30 1b [2] 77 19 [2] 30 08 [2] 7e 04 [2] 72 0e [2] 65 05 [2] 7e 4b [2] 43 }

  condition:
    any of them
}