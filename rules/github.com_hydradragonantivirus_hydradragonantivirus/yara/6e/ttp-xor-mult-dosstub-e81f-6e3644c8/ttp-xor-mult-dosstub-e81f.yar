rule TTP_XOR_MULT_DOSStub_e81f {
  strings:
    $key_e81f = { bc 77 [2] c8 6f [2] 8f 6d [2] c8 7c [2] 86 70 [2] 8a 7a [2] 9d 71 [2] 86 3f [2] bb }

  condition:
    any of them
}