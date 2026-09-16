rule TTP_XOR_MULT_DOSStub_1d7f {
  strings:
    $key_1d7f = { 49 17 [2] 3d 0f [2] 7a 0d [2] 3d 1c [2] 73 10 [2] 7f 1a [2] 68 11 [2] 73 5f [2] 4e }

  condition:
    any of them
}