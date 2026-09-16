rule TTP_XOR_MULT_DOSStub_056b {
  strings:
    $key_056b = { 51 03 [2] 25 1b [2] 62 19 [2] 25 08 [2] 6b 04 [2] 67 0e [2] 70 05 [2] 6b 4b [2] 56 }

  condition:
    any of them
}