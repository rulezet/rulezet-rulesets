rule TTP_XOR_MULT_DOSStub_2f4a {
  strings:
    $key_2f4a = { 7b 22 [2] 0f 3a [2] 48 38 [2] 0f 29 [2] 41 25 [2] 4d 2f [2] 5a 24 [2] 41 6a [2] 7c }

  condition:
    any of them
}