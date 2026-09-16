rule TTP_XOR_MULT_DOSStub_266b {
  strings:
    $key_266b = { 72 03 [2] 06 1b [2] 41 19 [2] 06 08 [2] 48 04 [2] 44 0e [2] 53 05 [2] 48 4b [2] 75 }

  condition:
    any of them
}