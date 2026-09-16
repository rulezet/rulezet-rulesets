rule TTP_XOR_MULT_DOSStub_566b {
  strings:
    $key_566b = { 02 03 [2] 76 1b [2] 31 19 [2] 76 08 [2] 38 04 [2] 34 0e [2] 23 05 [2] 38 4b [2] 05 }

  condition:
    any of them
}