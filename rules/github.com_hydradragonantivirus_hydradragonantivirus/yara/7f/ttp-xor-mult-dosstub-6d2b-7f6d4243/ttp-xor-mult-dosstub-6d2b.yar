rule TTP_XOR_MULT_DOSStub_6d2b {
  strings:
    $key_6d2b = { 39 43 [2] 4d 5b [2] 0a 59 [2] 4d 48 [2] 03 44 [2] 0f 4e [2] 18 45 [2] 03 0b [2] 3e }

  condition:
    any of them
}