rule TTP_XOR_MULT_DOSStub_7d3d {
  strings:
    $key_7d3d = { 29 55 [2] 5d 4d [2] 1a 4f [2] 5d 5e [2] 13 52 [2] 1f 58 [2] 08 53 [2] 13 1d [2] 2e }

  condition:
    any of them
}