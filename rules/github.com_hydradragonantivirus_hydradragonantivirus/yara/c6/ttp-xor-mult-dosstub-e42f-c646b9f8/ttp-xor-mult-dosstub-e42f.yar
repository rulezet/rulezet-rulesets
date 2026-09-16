rule TTP_XOR_MULT_DOSStub_e42f {
  strings:
    $key_e42f = { b0 47 [2] c4 5f [2] 83 5d [2] c4 4c [2] 8a 40 [2] 86 4a [2] 91 41 [2] 8a 0f [2] b7 }

  condition:
    any of them
}