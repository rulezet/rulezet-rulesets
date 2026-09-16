rule TTP_XOR_MULT_DOSStub_e80f {
  strings:
    $key_e80f = { bc 67 [2] c8 7f [2] 8f 7d [2] c8 6c [2] 86 60 [2] 8a 6a [2] 9d 61 [2] 86 2f [2] bb }

  condition:
    any of them
}