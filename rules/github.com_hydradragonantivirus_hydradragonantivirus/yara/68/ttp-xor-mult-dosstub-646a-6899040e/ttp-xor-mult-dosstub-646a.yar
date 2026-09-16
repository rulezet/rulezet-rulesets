rule TTP_XOR_MULT_DOSStub_646a {
  strings:
    $key_646a = { 30 02 [2] 44 1a [2] 03 18 [2] 44 09 [2] 0a 05 [2] 06 0f [2] 11 04 [2] 0a 4a [2] 37 }

  condition:
    any of them
}