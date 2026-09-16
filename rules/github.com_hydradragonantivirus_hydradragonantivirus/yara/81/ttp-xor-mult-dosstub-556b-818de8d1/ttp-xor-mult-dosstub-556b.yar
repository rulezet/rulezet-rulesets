rule TTP_XOR_MULT_DOSStub_556b {
  strings:
    $key_556b = { 01 03 [2] 75 1b [2] 32 19 [2] 75 08 [2] 3b 04 [2] 37 0e [2] 20 05 [2] 3b 4b [2] 06 }

  condition:
    any of them
}