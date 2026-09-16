rule TTP_XOR_MULT_DOSStub_e21f {
  strings:
    $key_e21f = { b6 77 [2] c2 6f [2] 85 6d [2] c2 7c [2] 8c 70 [2] 80 7a [2] 97 71 [2] 8c 3f [2] b1 }

  condition:
    any of them
}