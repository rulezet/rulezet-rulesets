rule TTP_XOR_MULT_DOSStub_5a6f {
  strings:
    $key_5a6f = { 0e 07 [2] 7a 1f [2] 3d 1d [2] 7a 0c [2] 34 00 [2] 38 0a [2] 2f 01 [2] 34 4f [2] 09 }

  condition:
    any of them
}