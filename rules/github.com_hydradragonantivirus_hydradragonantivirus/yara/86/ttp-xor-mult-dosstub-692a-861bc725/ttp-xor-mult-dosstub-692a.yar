rule TTP_XOR_MULT_DOSStub_692a {
  strings:
    $key_692a = { 3d 42 [2] 49 5a [2] 0e 58 [2] 49 49 [2] 07 45 [2] 0b 4f [2] 1c 44 [2] 07 0a [2] 3a }

  condition:
    any of them
}