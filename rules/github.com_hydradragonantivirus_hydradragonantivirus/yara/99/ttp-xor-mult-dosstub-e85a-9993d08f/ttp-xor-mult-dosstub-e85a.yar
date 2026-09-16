rule TTP_XOR_MULT_DOSStub_e85a {
  strings:
    $key_e85a = { bc 32 [2] c8 2a [2] 8f 28 [2] c8 39 [2] 86 35 [2] 8a 3f [2] 9d 34 [2] 86 7a [2] bb }

  condition:
    any of them
}