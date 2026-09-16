rule TTP_XOR_MULT_DOSStub_186b {
  strings:
    $key_186b = { 4c 03 [2] 38 1b [2] 7f 19 [2] 38 08 [2] 76 04 [2] 7a 0e [2] 6d 05 [2] 76 4b [2] 4b }

  condition:
    any of them
}