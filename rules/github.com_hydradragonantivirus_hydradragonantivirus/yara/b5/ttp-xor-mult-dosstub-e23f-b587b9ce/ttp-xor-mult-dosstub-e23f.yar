rule TTP_XOR_MULT_DOSStub_e23f {
  strings:
    $key_e23f = { b6 57 [2] c2 4f [2] 85 4d [2] c2 5c [2] 8c 50 [2] 80 5a [2] 97 51 [2] 8c 1f [2] b1 }

  condition:
    any of them
}