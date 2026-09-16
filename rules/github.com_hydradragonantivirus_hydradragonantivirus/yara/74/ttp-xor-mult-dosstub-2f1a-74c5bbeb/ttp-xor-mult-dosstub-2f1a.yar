rule TTP_XOR_MULT_DOSStub_2f1a {
  strings:
    $key_2f1a = { 7b 72 [2] 0f 6a [2] 48 68 [2] 0f 79 [2] 41 75 [2] 4d 7f [2] 5a 74 [2] 41 3a [2] 7c }

  condition:
    any of them
}