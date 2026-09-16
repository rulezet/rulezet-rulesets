rule TTP_XOR_MULT_DOSStub_e84a {
  strings:
    $key_e84a = { bc 22 [2] c8 3a [2] 8f 38 [2] c8 29 [2] 86 25 [2] 8a 2f [2] 9d 24 [2] 86 6a [2] bb }

  condition:
    any of them
}