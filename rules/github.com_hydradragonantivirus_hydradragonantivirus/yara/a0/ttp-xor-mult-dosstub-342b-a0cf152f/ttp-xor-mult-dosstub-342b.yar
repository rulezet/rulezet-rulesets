rule TTP_XOR_MULT_DOSStub_342b {
  strings:
    $key_342b = { 60 43 [2] 14 5b [2] 53 59 [2] 14 48 [2] 5a 44 [2] 56 4e [2] 41 45 [2] 5a 0b [2] 67 }

  condition:
    any of them
}