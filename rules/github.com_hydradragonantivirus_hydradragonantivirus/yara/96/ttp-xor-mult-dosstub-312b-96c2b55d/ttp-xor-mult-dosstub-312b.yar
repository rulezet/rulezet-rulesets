rule TTP_XOR_MULT_DOSStub_312b {
  strings:
    $key_312b = { 65 43 [2] 11 5b [2] 56 59 [2] 11 48 [2] 5f 44 [2] 53 4e [2] 44 45 [2] 5f 0b [2] 62 }

  condition:
    any of them
}