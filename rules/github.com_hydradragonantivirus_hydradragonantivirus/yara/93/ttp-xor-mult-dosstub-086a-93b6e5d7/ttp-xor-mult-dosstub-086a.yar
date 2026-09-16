rule TTP_XOR_MULT_DOSStub_086a {
  strings:
    $key_086a = { 5c 02 [2] 28 1a [2] 6f 18 [2] 28 09 [2] 66 05 [2] 6a 0f [2] 7d 04 [2] 66 4a [2] 5b }

  condition:
    any of them
}