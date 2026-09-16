rule TTP_XOR_MULT_DOSStub_e81a {
  strings:
    $key_e81a = { bc 72 [2] c8 6a [2] 8f 68 [2] c8 79 [2] 86 75 [2] 8a 7f [2] 9d 74 [2] 86 3a [2] bb }

  condition:
    any of them
}