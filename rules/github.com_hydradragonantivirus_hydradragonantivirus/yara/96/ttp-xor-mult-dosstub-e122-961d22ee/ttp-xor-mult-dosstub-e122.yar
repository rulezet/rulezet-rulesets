rule TTP_XOR_MULT_DOSStub_e122 {
  strings:
    $key_e122 = { b5 4a [2] c1 52 [2] 86 50 [2] c1 41 [2] 8f 4d [2] 83 47 [2] 94 4c [2] 8f 02 [2] b2 }

  condition:
    any of them
}