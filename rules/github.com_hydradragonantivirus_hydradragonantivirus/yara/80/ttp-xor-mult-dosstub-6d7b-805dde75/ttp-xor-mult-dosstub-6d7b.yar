rule TTP_XOR_MULT_DOSStub_6d7b {
  strings:
    $key_6d7b = { 39 13 [2] 4d 0b [2] 0a 09 [2] 4d 18 [2] 03 14 [2] 0f 1e [2] 18 15 [2] 03 5b [2] 3e }

  condition:
    any of them
}