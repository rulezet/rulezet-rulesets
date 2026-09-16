rule TTP_XOR_MULT_DOSStub_736a {
  strings:
    $key_736a = { 27 02 [2] 53 1a [2] 14 18 [2] 53 09 [2] 1d 05 [2] 11 0f [2] 06 04 [2] 1d 4a [2] 20 }

  condition:
    any of them
}