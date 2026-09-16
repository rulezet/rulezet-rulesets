rule TTP_XOR_MULT_DOSStub_e86f {
  strings:
    $key_e86f = { bc 07 [2] c8 1f [2] 8f 1d [2] c8 0c [2] 86 00 [2] 8a 0a [2] 9d 01 [2] 86 4f [2] bb }

  condition:
    any of them
}