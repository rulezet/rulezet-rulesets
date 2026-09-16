rule TTP_XOR_MULT_DOSStub_432b {
  strings:
    $key_432b = { 17 43 [2] 63 5b [2] 24 59 [2] 63 48 [2] 2d 44 [2] 21 4e [2] 36 45 [2] 2d 0b [2] 10 }

  condition:
    any of them
}