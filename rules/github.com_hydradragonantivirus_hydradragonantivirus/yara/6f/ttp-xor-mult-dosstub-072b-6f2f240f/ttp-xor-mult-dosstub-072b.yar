rule TTP_XOR_MULT_DOSStub_072b {
  strings:
    $key_072b = { 53 43 [2] 27 5b [2] 60 59 [2] 27 48 [2] 69 44 [2] 65 4e [2] 72 45 [2] 69 0b [2] 54 }

  condition:
    any of them
}