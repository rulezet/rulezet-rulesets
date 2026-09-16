rule TTP_XOR_MULT_DOSStub_262b {
  strings:
    $key_262b = { 72 43 [2] 06 5b [2] 41 59 [2] 06 48 [2] 48 44 [2] 44 4e [2] 53 45 [2] 48 0b [2] 75 }

  condition:
    any of them
}