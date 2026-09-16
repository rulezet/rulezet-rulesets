rule TTP_XOR_MULT_DOSStub_e022 {
  strings:
    $key_e022 = { b4 4a [2] c0 52 [2] 87 50 [2] c0 41 [2] 8e 4d [2] 82 47 [2] 95 4c [2] 8e 02 [2] b3 }

  condition:
    any of them
}