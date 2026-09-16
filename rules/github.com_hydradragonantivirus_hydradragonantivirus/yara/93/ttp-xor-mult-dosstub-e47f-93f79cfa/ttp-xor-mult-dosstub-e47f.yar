rule TTP_XOR_MULT_DOSStub_e47f {
  strings:
    $key_e47f = { b0 17 [2] c4 0f [2] 83 0d [2] c4 1c [2] 8a 10 [2] 86 1a [2] 91 11 [2] 8a 5f [2] b7 }

  condition:
    any of them
}