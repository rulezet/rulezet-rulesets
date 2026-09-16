rule TTP_XOR_MULT_DOSStub_772b {
  strings:
    $key_772b = { 23 43 [2] 57 5b [2] 10 59 [2] 57 48 [2] 19 44 [2] 15 4e [2] 02 45 [2] 19 0b [2] 24 }

  condition:
    any of them
}