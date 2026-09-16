rule TTP_XOR_MULT_DOSStub_e25f {
  strings:
    $key_e25f = { b6 37 [2] c2 2f [2] 85 2d [2] c2 3c [2] 8c 30 [2] 80 3a [2] 97 31 [2] 8c 7f [2] b1 }

  condition:
    any of them
}