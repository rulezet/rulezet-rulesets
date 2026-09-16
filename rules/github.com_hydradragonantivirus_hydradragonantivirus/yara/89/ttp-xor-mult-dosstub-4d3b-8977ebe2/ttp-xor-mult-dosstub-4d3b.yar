rule TTP_XOR_MULT_DOSStub_4d3b {
  strings:
    $key_4d3b = { 19 53 [2] 6d 4b [2] 2a 49 [2] 6d 58 [2] 23 54 [2] 2f 5e [2] 38 55 [2] 23 1b [2] 1e }

  condition:
    any of them
}