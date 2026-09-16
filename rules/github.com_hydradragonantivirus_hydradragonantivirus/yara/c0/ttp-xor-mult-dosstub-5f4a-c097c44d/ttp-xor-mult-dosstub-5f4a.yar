rule TTP_XOR_MULT_DOSStub_5f4a {
  strings:
    $key_5f4a = { 0b 22 [2] 7f 3a [2] 38 38 [2] 7f 29 [2] 31 25 [2] 3d 2f [2] 2a 24 [2] 31 6a [2] 0c }

  condition:
    any of them
}