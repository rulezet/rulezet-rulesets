rule TTP_XOR_MULT_DOSStub_e82f {
  strings:
    $key_e82f = { bc 47 [2] c8 5f [2] 8f 5d [2] c8 4c [2] 86 40 [2] 8a 4a [2] 9d 41 [2] 86 0f [2] bb }

  condition:
    any of them
}