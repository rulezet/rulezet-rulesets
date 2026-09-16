rule TTP_XOR_MULT_DOSStub_056a {
  strings:
    $key_056a = { 51 02 [2] 25 1a [2] 62 18 [2] 25 09 [2] 6b 05 [2] 67 0f [2] 70 04 [2] 6b 4a [2] 56 }

  condition:
    any of them
}