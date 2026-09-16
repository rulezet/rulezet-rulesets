rule TTP_XOR_MULT_DOSStub_2a6b {
  strings:
    $key_2a6b = { 7e 03 [2] 0a 1b [2] 4d 19 [2] 0a 08 [2] 44 04 [2] 48 0e [2] 5f 05 [2] 44 4b [2] 79 }

  condition:
    any of them
}