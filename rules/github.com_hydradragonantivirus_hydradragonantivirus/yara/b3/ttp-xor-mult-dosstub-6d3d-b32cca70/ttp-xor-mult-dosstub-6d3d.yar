rule TTP_XOR_MULT_DOSStub_6d3d {
  strings:
    $key_6d3d = { 39 55 [2] 4d 4d [2] 0a 4f [2] 4d 5e [2] 03 52 [2] 0f 58 [2] 18 53 [2] 03 1d [2] 3e }

  condition:
    any of them
}