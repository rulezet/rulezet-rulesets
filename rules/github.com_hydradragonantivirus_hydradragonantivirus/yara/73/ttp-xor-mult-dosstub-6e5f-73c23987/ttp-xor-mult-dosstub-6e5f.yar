rule TTP_XOR_MULT_DOSStub_6e5f {
  strings:
    $key_6e5f = { 3a 37 [2] 4e 2f [2] 09 2d [2] 4e 3c [2] 00 30 [2] 0c 3a [2] 1b 31 [2] 00 7f [2] 3d }

  condition:
    any of them
}