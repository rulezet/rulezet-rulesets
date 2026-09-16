rule TTP_XOR_MULT_DOSStub_071a {
  strings:
    $key_071a = { 53 72 [2] 27 6a [2] 60 68 [2] 27 79 [2] 69 75 [2] 65 7f [2] 72 74 [2] 69 3a [2] 54 }

  condition:
    any of them
}