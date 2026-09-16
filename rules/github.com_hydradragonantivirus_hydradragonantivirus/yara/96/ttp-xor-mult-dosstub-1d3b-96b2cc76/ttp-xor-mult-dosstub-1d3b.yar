rule TTP_XOR_MULT_DOSStub_1d3b {
  strings:
    $key_1d3b = { 49 53 [2] 3d 4b [2] 7a 49 [2] 3d 58 [2] 73 54 [2] 7f 5e [2] 68 55 [2] 73 1b [2] 4e }

  condition:
    any of them
}