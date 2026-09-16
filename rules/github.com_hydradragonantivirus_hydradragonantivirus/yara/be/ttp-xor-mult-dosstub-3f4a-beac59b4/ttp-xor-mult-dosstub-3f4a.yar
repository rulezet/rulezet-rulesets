rule TTP_XOR_MULT_DOSStub_3f4a {
  strings:
    $key_3f4a = { 6b 22 [2] 1f 3a [2] 58 38 [2] 1f 29 [2] 51 25 [2] 5d 2f [2] 4a 24 [2] 51 6a [2] 6c }

  condition:
    any of them
}