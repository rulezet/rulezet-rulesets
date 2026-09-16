rule TTP_XOR_MULT_DOSStub_5f2a {
  strings:
    $key_5f2a = { 0b 42 [2] 7f 5a [2] 38 58 [2] 7f 49 [2] 31 45 [2] 3d 4f [2] 2a 44 [2] 31 0a [2] 0c }

  condition:
    any of them
}