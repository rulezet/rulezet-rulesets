rule TTP_XOR_MULT_DOSStub_316a {
  strings:
    $key_316a = { 65 02 [2] 11 1a [2] 56 18 [2] 11 09 [2] 5f 05 [2] 53 0f [2] 44 04 [2] 5f 4a [2] 62 }

  condition:
    any of them
}