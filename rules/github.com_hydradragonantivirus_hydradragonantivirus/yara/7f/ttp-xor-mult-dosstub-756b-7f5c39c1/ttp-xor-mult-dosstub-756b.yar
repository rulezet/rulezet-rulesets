rule TTP_XOR_MULT_DOSStub_756b {
  strings:
    $key_756b = { 21 03 [2] 55 1b [2] 12 19 [2] 55 08 [2] 1b 04 [2] 17 0e [2] 00 05 [2] 1b 4b [2] 26 }

  condition:
    any of them
}