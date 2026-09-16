rule TTP_XOR_MULT_DOSStub_646b {
  strings:
    $key_646b = { 30 03 [2] 44 1b [2] 03 19 [2] 44 08 [2] 0a 04 [2] 06 0e [2] 11 05 [2] 0a 4b [2] 37 }

  condition:
    any of them
}