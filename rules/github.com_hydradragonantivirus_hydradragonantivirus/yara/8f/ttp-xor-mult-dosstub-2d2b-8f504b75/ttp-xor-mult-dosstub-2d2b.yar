rule TTP_XOR_MULT_DOSStub_2d2b {
  strings:
    $key_2d2b = { 79 43 [2] 0d 5b [2] 4a 59 [2] 0d 48 [2] 43 44 [2] 4f 4e [2] 58 45 [2] 43 0b [2] 7e }

  condition:
    any of them
}