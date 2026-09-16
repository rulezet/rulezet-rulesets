rule TTP_XOR_MULT_DOSStub_393b {
  strings:
    $key_393b = { 6d 53 [2] 19 4b [2] 5e 49 [2] 19 58 [2] 57 54 [2] 5b 5e [2] 4c 55 [2] 57 1b [2] 6a }

  condition:
    any of them
}