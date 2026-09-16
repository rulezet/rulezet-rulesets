rule TTP_XOR_MULT_DOSStub_487f {
  strings:
    $key_487f = { 1c 17 [2] 68 0f [2] 2f 0d [2] 68 1c [2] 26 10 [2] 2a 1a [2] 3d 11 [2] 26 5f [2] 1b }

  condition:
    any of them
}