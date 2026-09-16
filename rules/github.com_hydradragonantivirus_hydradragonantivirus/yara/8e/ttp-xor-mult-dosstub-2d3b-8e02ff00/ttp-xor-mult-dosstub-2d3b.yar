rule TTP_XOR_MULT_DOSStub_2d3b {
  strings:
    $key_2d3b = { 79 53 [2] 0d 4b [2] 4a 49 [2] 0d 58 [2] 43 54 [2] 4f 5e [2] 58 55 [2] 43 1b [2] 7e }

  condition:
    any of them
}