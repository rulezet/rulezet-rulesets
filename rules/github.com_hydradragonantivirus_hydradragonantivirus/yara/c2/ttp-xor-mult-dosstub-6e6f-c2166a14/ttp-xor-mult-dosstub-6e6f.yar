rule TTP_XOR_MULT_DOSStub_6e6f {
  strings:
    $key_6e6f = { 3a 07 [2] 4e 1f [2] 09 1d [2] 4e 0c [2] 00 00 [2] 0c 0a [2] 1b 01 [2] 00 4f [2] 3d }

  condition:
    any of them
}