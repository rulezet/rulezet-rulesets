rule TTP_XOR_MULT_DOSStub_5b6b {
  strings:
    $key_5b6b = { 0f 03 [2] 7b 1b [2] 3c 19 [2] 7b 08 [2] 35 04 [2] 39 0e [2] 2e 05 [2] 35 4b [2] 08 }

  condition:
    any of them
}