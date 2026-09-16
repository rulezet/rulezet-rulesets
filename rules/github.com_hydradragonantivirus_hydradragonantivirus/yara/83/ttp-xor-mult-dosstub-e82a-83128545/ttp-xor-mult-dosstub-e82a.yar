rule TTP_XOR_MULT_DOSStub_e82a {
  strings:
    $key_e82a = { bc 42 [2] c8 5a [2] 8f 58 [2] c8 49 [2] 86 45 [2] 8a 4f [2] 9d 44 [2] 86 0a [2] bb }

  condition:
    any of them
}