rule TTP_XOR_MULT_DOSStub_503b {
  strings:
    $key_503b = { 04 53 [2] 70 4b [2] 37 49 [2] 70 58 [2] 3e 54 [2] 32 5e [2] 25 55 [2] 3e 1b [2] 03 }

  condition:
    any of them
}