rule TTP_XOR_MULT_DOSStub_103b {
  strings:
    $key_103b = { 44 53 [2] 30 4b [2] 77 49 [2] 30 58 [2] 7e 54 [2] 72 5e [2] 65 55 [2] 7e 1b [2] 43 }

  condition:
    any of them
}