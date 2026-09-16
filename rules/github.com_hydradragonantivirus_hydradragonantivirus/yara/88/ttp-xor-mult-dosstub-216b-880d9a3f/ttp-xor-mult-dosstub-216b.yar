rule TTP_XOR_MULT_DOSStub_216b {
  strings:
    $key_216b = { 75 03 [2] 01 1b [2] 46 19 [2] 01 08 [2] 4f 04 [2] 43 0e [2] 54 05 [2] 4f 4b [2] 72 }

  condition:
    any of them
}