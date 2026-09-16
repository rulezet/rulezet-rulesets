rule TTP_XOR_MULT_DOSStub_3f7a {
  strings:
    $key_3f7a = { 6b 12 [2] 1f 0a [2] 58 08 [2] 1f 19 [2] 51 15 [2] 5d 1f [2] 4a 14 [2] 51 5a [2] 6c }

  condition:
    any of them
}