rule TTP_XOR_MULT_DOSStub_4d3d {
  strings:
    $key_4d3d = { 19 55 [2] 6d 4d [2] 2a 4f [2] 6d 5e [2] 23 52 [2] 2f 58 [2] 38 53 [2] 23 1d [2] 1e }

  condition:
    any of them
}