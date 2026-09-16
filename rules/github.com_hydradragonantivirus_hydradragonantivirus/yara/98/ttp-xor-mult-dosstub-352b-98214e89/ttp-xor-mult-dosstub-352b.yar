rule TTP_XOR_MULT_DOSStub_352b {
  strings:
    $key_352b = { 61 43 [2] 15 5b [2] 52 59 [2] 15 48 [2] 5b 44 [2] 57 4e [2] 40 45 [2] 5b 0b [2] 66 }

  condition:
    any of them
}