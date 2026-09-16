rule TTP_XOR_MULT_DOSStub_262d {
  strings:
    $key_262d = { 72 45 [2] 06 5d [2] 41 5f [2] 06 4e [2] 48 42 [2] 44 48 [2] 53 43 [2] 48 0d [2] 75 }

  condition:
    any of them
}