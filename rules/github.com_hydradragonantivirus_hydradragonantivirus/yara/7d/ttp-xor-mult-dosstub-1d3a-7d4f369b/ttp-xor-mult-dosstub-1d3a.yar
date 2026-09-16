rule TTP_XOR_MULT_DOSStub_1d3a {
  strings:
    $key_1d3a = { 49 52 [2] 3d 4a [2] 7a 48 [2] 3d 59 [2] 73 55 [2] 7f 5f [2] 68 54 [2] 73 1a [2] 4e }

  condition:
    any of them
}