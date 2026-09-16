rule TTP_XOR_MULT_DOSStub_e77f {
  strings:
    $key_e77f = { b3 17 [2] c7 0f [2] 80 0d [2] c7 1c [2] 89 10 [2] 85 1a [2] 92 11 [2] 89 5f [2] b4 }

  condition:
    any of them
}