rule TTP_XOR_MULT_DOSStub_532a {
  strings:
    $key_532a = { 07 42 [2] 73 5a [2] 34 58 [2] 73 49 [2] 3d 45 [2] 31 4f [2] 26 44 [2] 3d 0a [2] 00 }

  condition:
    any of them
}