rule TTP_XOR_MULT_DOSStub_1d5a {
  strings:
    $key_1d5a = { 49 32 [2] 3d 2a [2] 7a 28 [2] 3d 39 [2] 73 35 [2] 7f 3f [2] 68 34 [2] 73 7a [2] 4e }

  condition:
    any of them
}