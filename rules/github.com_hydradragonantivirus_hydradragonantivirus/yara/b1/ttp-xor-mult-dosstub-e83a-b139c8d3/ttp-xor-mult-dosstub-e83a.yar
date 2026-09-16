rule TTP_XOR_MULT_DOSStub_e83a {
  strings:
    $key_e83a = { bc 52 [2] c8 4a [2] 8f 48 [2] c8 59 [2] 86 55 [2] 8a 5f [2] 9d 54 [2] 86 1a [2] bb }

  condition:
    any of them
}