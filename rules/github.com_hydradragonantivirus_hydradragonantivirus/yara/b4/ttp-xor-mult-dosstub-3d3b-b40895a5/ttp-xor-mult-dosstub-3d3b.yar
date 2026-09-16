rule TTP_XOR_MULT_DOSStub_3d3b {
  strings:
    $key_3d3b = { 69 53 [2] 1d 4b [2] 5a 49 [2] 1d 58 [2] 53 54 [2] 5f 5e [2] 48 55 [2] 53 1b [2] 6e }

  condition:
    any of them
}