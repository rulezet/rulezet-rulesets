rule TTP_XOR_MULT_DOSStub_187a {
  strings:
    $key_187a = { 4c 12 [2] 38 0a [2] 7f 08 [2] 38 19 [2] 76 15 [2] 7a 1f [2] 6d 14 [2] 76 5a [2] 4b }

  condition:
    any of them
}