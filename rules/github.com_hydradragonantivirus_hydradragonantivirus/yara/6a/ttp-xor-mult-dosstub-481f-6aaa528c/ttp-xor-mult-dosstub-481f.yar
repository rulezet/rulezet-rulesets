rule TTP_XOR_MULT_DOSStub_481f {
  strings:
    $key_481f = { 1c 77 [2] 68 6f [2] 2f 6d [2] 68 7c [2] 26 70 [2] 2a 7a [2] 3d 71 [2] 26 3f [2] 1b }

  condition:
    any of them
}