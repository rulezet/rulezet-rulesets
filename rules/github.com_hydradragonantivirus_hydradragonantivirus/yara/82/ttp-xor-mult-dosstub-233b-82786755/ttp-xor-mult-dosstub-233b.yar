rule TTP_XOR_MULT_DOSStub_233b {
  strings:
    $key_233b = { 77 53 [2] 03 4b [2] 44 49 [2] 03 58 [2] 4d 54 [2] 41 5e [2] 56 55 [2] 4d 1b [2] 70 }

  condition:
    any of them
}