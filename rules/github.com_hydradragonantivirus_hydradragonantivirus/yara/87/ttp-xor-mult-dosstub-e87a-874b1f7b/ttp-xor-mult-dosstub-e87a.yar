rule TTP_XOR_MULT_DOSStub_e87a {
  strings:
    $key_e87a = { bc 12 [2] c8 0a [2] 8f 08 [2] c8 19 [2] 86 15 [2] 8a 1f [2] 9d 14 [2] 86 5a [2] bb }

  condition:
    any of them
}