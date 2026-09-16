rule TTP_XOR_MULT_DOSStub_1d3d {
  strings:
    $key_1d3d = { 49 55 [2] 3d 4d [2] 7a 4f [2] 3d 5e [2] 73 52 [2] 7f 58 [2] 68 53 [2] 73 1d [2] 4e }

  condition:
    any of them
}