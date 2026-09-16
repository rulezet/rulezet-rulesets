rule TTP_XOR_MULT_DOSStub_6f7a {
  strings:
    $key_6f7a = { 3b 12 [2] 4f 0a [2] 08 08 [2] 4f 19 [2] 01 15 [2] 0d 1f [2] 1a 14 [2] 01 5a [2] 3c }

  condition:
    any of them
}