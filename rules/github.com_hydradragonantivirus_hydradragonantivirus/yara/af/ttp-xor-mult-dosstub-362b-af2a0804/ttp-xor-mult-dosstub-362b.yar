rule TTP_XOR_MULT_DOSStub_362b {
  strings:
    $key_362b = { 62 43 [2] 16 5b [2] 51 59 [2] 16 48 [2] 58 44 [2] 54 4e [2] 43 45 [2] 58 0b [2] 65 }

  condition:
    any of them
}