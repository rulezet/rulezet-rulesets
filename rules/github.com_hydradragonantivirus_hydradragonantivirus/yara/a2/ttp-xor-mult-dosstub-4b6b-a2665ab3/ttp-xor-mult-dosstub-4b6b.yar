rule TTP_XOR_MULT_DOSStub_4b6b {
  strings:
    $key_4b6b = { 1f 03 [2] 6b 1b [2] 2c 19 [2] 6b 08 [2] 25 04 [2] 29 0e [2] 3e 05 [2] 25 4b [2] 18 }

  condition:
    any of them
}