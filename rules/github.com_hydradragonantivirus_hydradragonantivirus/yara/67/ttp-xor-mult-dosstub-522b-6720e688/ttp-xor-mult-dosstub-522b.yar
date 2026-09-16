rule TTP_XOR_MULT_DOSStub_522b {
  strings:
    $key_522b = { 06 43 [2] 72 5b [2] 35 59 [2] 72 48 [2] 3c 44 [2] 30 4e [2] 27 45 [2] 3c 0b [2] 01 }

  condition:
    any of them
}