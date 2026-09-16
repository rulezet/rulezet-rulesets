rule TTP_XOR_MULT_DOSStub_462b {
  strings:
    $key_462b = { 12 43 [2] 66 5b [2] 21 59 [2] 66 48 [2] 28 44 [2] 24 4e [2] 33 45 [2] 28 0b [2] 15 }

  condition:
    any of them
}