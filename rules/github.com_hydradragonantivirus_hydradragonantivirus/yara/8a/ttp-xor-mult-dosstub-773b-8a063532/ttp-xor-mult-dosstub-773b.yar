rule TTP_XOR_MULT_DOSStub_773b {
  strings:
    $key_773b = { 23 53 [2] 57 4b [2] 10 49 [2] 57 58 [2] 19 54 [2] 15 5e [2] 02 55 [2] 19 1b [2] 24 }

  condition:
    any of them
}