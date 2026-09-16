rule TTP_XOR_MULT_DOSStub_3d3d {
  strings:
    $key_3d3d = { 69 55 [2] 1d 4d [2] 5a 4f [2] 1d 5e [2] 53 52 [2] 5f 58 [2] 48 53 [2] 53 1d [2] 6e }

  condition:
    any of them
}