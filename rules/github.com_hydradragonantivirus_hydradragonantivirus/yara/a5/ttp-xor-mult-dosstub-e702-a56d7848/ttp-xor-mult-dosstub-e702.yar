rule TTP_XOR_MULT_DOSStub_e702 {
  strings:
    $key_e702 = { b3 6a [2] c7 72 [2] 80 70 [2] c7 61 [2] 89 6d [2] 85 67 [2] 92 6c [2] 89 22 [2] b4 }

  condition:
    any of them
}