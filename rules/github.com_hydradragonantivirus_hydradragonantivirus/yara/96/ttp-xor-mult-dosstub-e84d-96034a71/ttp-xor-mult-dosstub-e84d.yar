rule TTP_XOR_MULT_DOSStub_e84d {
  strings:
    $key_e84d = { bc 25 [2] c8 3d [2] 8f 3f [2] c8 2e [2] 86 22 [2] 8a 28 [2] 9d 23 [2] 86 6d [2] bb }

  condition:
    any of them
}