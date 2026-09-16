rule TTP_XOR_MULT_DOSStub_485f {
  strings:
    $key_485f = { 1c 37 [2] 68 2f [2] 2f 2d [2] 68 3c [2] 26 30 [2] 2a 3a [2] 3d 31 [2] 26 7f [2] 1b }

  condition:
    any of them
}