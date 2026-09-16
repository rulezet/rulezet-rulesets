rule TTP_XOR_MULT_DOSStub_303b {
  strings:
    $key_303b = { 64 53 [2] 10 4b [2] 57 49 [2] 10 58 [2] 5e 54 [2] 52 5e [2] 45 55 [2] 5e 1b [2] 63 }

  condition:
    any of them
}