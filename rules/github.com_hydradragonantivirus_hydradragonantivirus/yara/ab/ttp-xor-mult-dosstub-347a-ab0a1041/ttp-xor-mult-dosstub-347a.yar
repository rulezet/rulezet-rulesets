rule TTP_XOR_MULT_DOSStub_347a {
  strings:
    $key_347a = { 60 12 [2] 14 0a [2] 53 08 [2] 14 19 [2] 5a 15 [2] 56 1f [2] 41 14 [2] 5a 5a [2] 67 }

  condition:
    any of them
}