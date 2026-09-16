rule TTP_XOR_MULT_DOSStub_3d3f {
  strings:
    $key_3d3f = { 69 57 [2] 1d 4f [2] 5a 4d [2] 1d 5c [2] 53 50 [2] 5f 5a [2] 48 51 [2] 53 1f [2] 6e }

  condition:
    any of them
}