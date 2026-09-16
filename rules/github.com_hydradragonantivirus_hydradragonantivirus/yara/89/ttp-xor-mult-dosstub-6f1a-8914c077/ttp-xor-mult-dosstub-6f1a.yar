rule TTP_XOR_MULT_DOSStub_6f1a {
  strings:
    $key_6f1a = { 3b 72 [2] 4f 6a [2] 08 68 [2] 4f 79 [2] 01 75 [2] 0d 7f [2] 1a 74 [2] 01 3a [2] 3c }

  condition:
    any of them
}