rule TTP_XOR_MULT_DOSStub_6d6b {
  strings:
    $key_6d6b = { 39 03 [2] 4d 1b [2] 0a 19 [2] 4d 08 [2] 03 04 [2] 0f 0e [2] 18 05 [2] 03 4b [2] 3e }

  condition:
    any of them
}