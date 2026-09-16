rule TTP_XOR_MULT_DOSStub_1b6b {
  strings:
    $key_1b6b = { 4f 03 [2] 3b 1b [2] 7c 19 [2] 3b 08 [2] 75 04 [2] 79 0e [2] 6e 05 [2] 75 4b [2] 48 }

  condition:
    any of them
}