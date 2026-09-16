rule TTP_XOR_MULT_DOSStub_776a {
  strings:
    $key_776a = { 23 02 [2] 57 1a [2] 10 18 [2] 57 09 [2] 19 05 [2] 15 0f [2] 02 04 [2] 19 4a [2] 24 }

  condition:
    any of them
}