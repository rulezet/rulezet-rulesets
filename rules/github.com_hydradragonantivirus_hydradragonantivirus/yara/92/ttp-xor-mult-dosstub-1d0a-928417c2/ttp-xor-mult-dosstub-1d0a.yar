rule TTP_XOR_MULT_DOSStub_1d0a {
  strings:
    $key_1d0a = { 49 62 [2] 3d 7a [2] 7a 78 [2] 3d 69 [2] 73 65 [2] 7f 6f [2] 68 64 [2] 73 2a [2] 4e }

  condition:
    any of them
}