rule TTP_XOR_MULT_DOSStub_696f {
  strings:
    $key_696f = { 3d 07 [2] 49 1f [2] 0e 1d [2] 49 0c [2] 07 00 [2] 0b 0a [2] 1c 01 [2] 07 4f [2] 3a }

  condition:
    any of them
}