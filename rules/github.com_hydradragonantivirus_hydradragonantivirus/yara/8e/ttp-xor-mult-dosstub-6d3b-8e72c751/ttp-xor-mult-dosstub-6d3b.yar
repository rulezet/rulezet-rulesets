rule TTP_XOR_MULT_DOSStub_6d3b {
  strings:
    $key_6d3b = { 39 53 [2] 4d 4b [2] 0a 49 [2] 4d 58 [2] 03 54 [2] 0f 5e [2] 18 55 [2] 03 1b [2] 3e }

  condition:
    any of them
}