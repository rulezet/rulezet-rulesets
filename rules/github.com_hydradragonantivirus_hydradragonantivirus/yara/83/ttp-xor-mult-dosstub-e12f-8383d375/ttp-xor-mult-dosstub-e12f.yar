rule TTP_XOR_MULT_DOSStub_e12f {
  strings:
    $key_e12f = { b5 47 [2] c1 5f [2] 86 5d [2] c1 4c [2] 8f 40 [2] 83 4a [2] 94 41 [2] 8f 0f [2] b2 }

  condition:
    any of them
}