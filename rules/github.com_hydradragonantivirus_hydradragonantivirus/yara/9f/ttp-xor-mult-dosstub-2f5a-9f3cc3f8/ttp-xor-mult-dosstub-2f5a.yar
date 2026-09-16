rule TTP_XOR_MULT_DOSStub_2f5a {
  strings:
    $key_2f5a = { 7b 32 [2] 0f 2a [2] 48 28 [2] 0f 39 [2] 41 35 [2] 4d 3f [2] 5a 34 [2] 41 7a [2] 7c }

  condition:
    any of them
}