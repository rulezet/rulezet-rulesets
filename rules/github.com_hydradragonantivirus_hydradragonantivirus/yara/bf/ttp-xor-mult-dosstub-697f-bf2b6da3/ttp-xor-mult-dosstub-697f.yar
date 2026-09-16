rule TTP_XOR_MULT_DOSStub_697f {
  strings:
    $key_697f = { 3d 17 [2] 49 0f [2] 0e 0d [2] 49 1c [2] 07 10 [2] 0b 1a [2] 1c 11 [2] 07 5f [2] 3a }

  condition:
    any of them
}