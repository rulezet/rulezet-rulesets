rule TTP_XOR_MULT_DOSStub_e75f {
  strings:
    $key_e75f = { b3 37 [2] c7 2f [2] 80 2d [2] c7 3c [2] 89 30 [2] 85 3a [2] 92 31 [2] 89 7f [2] b4 }

  condition:
    any of them
}