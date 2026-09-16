rule TTP_XOR_MULT_DOSStub_616b {
  strings:
    $key_616b = { 35 03 [2] 41 1b [2] 06 19 [2] 41 08 [2] 0f 04 [2] 03 0e [2] 14 05 [2] 0f 4b [2] 32 }

  condition:
    any of them
}