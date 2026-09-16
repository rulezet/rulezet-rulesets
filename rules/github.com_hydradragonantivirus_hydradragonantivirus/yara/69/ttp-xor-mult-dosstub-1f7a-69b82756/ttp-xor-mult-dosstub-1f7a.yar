rule TTP_XOR_MULT_DOSStub_1f7a {
  strings:
    $key_1f7a = { 4b 12 [2] 3f 0a [2] 78 08 [2] 3f 19 [2] 71 15 [2] 7d 1f [2] 6a 14 [2] 71 5a [2] 4c }

  condition:
    any of them
}