rule TTP_XOR_MULT_DOSStub_3f1a {
  strings:
    $key_3f1a = { 6b 72 [2] 1f 6a [2] 58 68 [2] 1f 79 [2] 51 75 [2] 5d 7f [2] 4a 74 [2] 51 3a [2] 6c }

  condition:
    any of them
}