rule TTP_XOR_MULT_DOSStub_737a {
  strings:
    $key_737a = { 27 12 [2] 53 0a [2] 14 08 [2] 53 19 [2] 1d 15 [2] 11 1f [2] 06 14 [2] 1d 5a [2] 20 }

  condition:
    any of them
}