rule TTP_XOR_MULT_DOSStub_5d6b {
  strings:
    $key_5d6b = { 09 03 [2] 7d 1b [2] 3a 19 [2] 7d 08 [2] 33 04 [2] 3f 0e [2] 28 05 [2] 33 4b [2] 0e }

  condition:
    any of them
}