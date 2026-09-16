rule TTP_XOR_MULT_DOSStub_002b {
  strings:
    $key_002b = { 54 43 [2] 20 5b [2] 67 59 [2] 20 48 [2] 6e 44 [2] 62 4e [2] 75 45 [2] 6e 0b [2] 53 }

  condition:
    any of them
}