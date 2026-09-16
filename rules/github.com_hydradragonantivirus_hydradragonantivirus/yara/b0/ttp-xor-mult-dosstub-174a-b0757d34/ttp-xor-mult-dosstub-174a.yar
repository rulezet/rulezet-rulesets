rule TTP_XOR_MULT_DOSStub_174a {
  strings:
    $key_174a = { 43 22 [2] 37 3a [2] 70 38 [2] 37 29 [2] 79 25 [2] 75 2f [2] 62 24 [2] 79 6a [2] 44 }

  condition:
    any of them
}