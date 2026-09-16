rule TTP_XOR_MULT_DOSStub_e83f {
  strings:
    $key_e83f = { bc 57 [2] c8 4f [2] 8f 4d [2] c8 5c [2] 86 50 [2] 8a 5a [2] 9d 51 [2] 86 1f [2] bb }

  condition:
    any of them
}