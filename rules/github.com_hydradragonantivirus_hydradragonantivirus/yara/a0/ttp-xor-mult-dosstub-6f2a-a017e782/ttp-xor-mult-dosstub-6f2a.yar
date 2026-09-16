rule TTP_XOR_MULT_DOSStub_6f2a {
  strings:
    $key_6f2a = { 3b 42 [2] 4f 5a [2] 08 58 [2] 4f 49 [2] 01 45 [2] 0d 4f [2] 1a 44 [2] 01 0a [2] 3c }

  condition:
    any of them
}