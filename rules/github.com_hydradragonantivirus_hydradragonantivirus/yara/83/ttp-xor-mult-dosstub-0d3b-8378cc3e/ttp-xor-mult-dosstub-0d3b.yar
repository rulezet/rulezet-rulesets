rule TTP_XOR_MULT_DOSStub_0d3b {
  strings:
    $key_0d3b = { 59 53 [2] 2d 4b [2] 6a 49 [2] 2d 58 [2] 63 54 [2] 6f 5e [2] 78 55 [2] 63 1b [2] 5e }

  condition:
    any of them
}