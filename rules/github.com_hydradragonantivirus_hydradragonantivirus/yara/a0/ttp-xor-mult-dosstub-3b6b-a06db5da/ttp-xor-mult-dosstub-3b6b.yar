rule TTP_XOR_MULT_DOSStub_3b6b {
  strings:
    $key_3b6b = { 6f 03 [2] 1b 1b [2] 5c 19 [2] 1b 08 [2] 55 04 [2] 59 0e [2] 4e 05 [2] 55 4b [2] 68 }

  condition:
    any of them
}