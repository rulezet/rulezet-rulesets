rule TTP_XOR_MULT_DOSStub_466a {
  strings:
    $key_466a = { 12 02 [2] 66 1a [2] 21 18 [2] 66 09 [2] 28 05 [2] 24 0f [2] 33 04 [2] 28 4a [2] 15 }

  condition:
    any of them
}