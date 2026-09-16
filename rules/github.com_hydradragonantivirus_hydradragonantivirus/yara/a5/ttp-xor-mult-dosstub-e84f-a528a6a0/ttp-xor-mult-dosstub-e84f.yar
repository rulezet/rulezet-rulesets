rule TTP_XOR_MULT_DOSStub_e84f {
  strings:
    $key_e84f = { bc 27 [2] c8 3f [2] 8f 3d [2] c8 2c [2] 86 20 [2] 8a 2a [2] 9d 21 [2] 86 6f [2] bb }

  condition:
    any of them
}