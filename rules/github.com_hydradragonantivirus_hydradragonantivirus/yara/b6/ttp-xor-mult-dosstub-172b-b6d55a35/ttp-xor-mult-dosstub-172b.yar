rule TTP_XOR_MULT_DOSStub_172b {
  strings:
    $key_172b = { 43 43 [2] 37 5b [2] 70 59 [2] 37 48 [2] 79 44 [2] 75 4e [2] 62 45 [2] 79 0b [2] 44 }

  condition:
    any of them
}