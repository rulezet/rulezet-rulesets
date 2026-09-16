rule TTP_XOR_MULT_DOSStub_485a {
  strings:
    $key_485a = { 1c 32 [2] 68 2a [2] 2f 28 [2] 68 39 [2] 26 35 [2] 2a 3f [2] 3d 34 [2] 26 7a [2] 1b }

  condition:
    any of them
}