rule TTP_XOR_MULT_DOSStub_436a {
  strings:
    $key_436a = { 17 02 [2] 63 1a [2] 24 18 [2] 63 09 [2] 2d 05 [2] 21 0f [2] 36 04 [2] 2d 4a [2] 10 }

  condition:
    any of them
}