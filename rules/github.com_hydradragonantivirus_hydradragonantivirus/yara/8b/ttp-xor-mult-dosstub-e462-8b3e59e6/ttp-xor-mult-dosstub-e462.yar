rule TTP_XOR_MULT_DOSStub_e462 {
  strings:
    $key_e462 = { b0 0a [2] c4 12 [2] 83 10 [2] c4 01 [2] 8a 0d [2] 86 07 [2] 91 0c [2] 8a 42 [2] b7 }

  condition:
    any of them
}