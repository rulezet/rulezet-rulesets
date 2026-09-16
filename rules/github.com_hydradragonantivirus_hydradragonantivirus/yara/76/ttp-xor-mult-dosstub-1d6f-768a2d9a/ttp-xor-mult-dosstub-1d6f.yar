rule TTP_XOR_MULT_DOSStub_1d6f {
  strings:
    $key_1d6f = { 49 07 [2] 3d 1f [2] 7a 1d [2] 3d 0c [2] 73 00 [2] 7f 0a [2] 68 01 [2] 73 4f [2] 4e }

  condition:
    any of them
}