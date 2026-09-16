rule TTP_XOR_MULT_DOSStub_0d3f {
  strings:
    $key_0d3f = { 59 57 [2] 2d 4f [2] 6a 4d [2] 2d 5c [2] 63 50 [2] 6f 5a [2] 78 51 [2] 63 1f [2] 5e }

  condition:
    any of them
}