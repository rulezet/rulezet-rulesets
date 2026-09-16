rule TTP_XOR_MULT_DOSStub_5a2a {
  strings:
    $key_5a2a = { 0e 42 [2] 7a 5a [2] 3d 58 [2] 7a 49 [2] 34 45 [2] 38 4f [2] 2f 44 [2] 34 0a [2] 09 }

  condition:
    any of them
}