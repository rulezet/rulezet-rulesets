rule TTP_XOR_MULT_DOSStub_353b {
  strings:
    $key_353b = { 61 53 [2] 15 4b [2] 52 49 [2] 15 58 [2] 5b 54 [2] 57 5e [2] 40 55 [2] 5b 1b [2] 66 }

  condition:
    any of them
}