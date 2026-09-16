rule TTP_XOR_MULT_DOSStub_e0e8 {
  strings:
    $key_e0e8 = { b4 80 [2] c0 98 [2] 87 9a [2] c0 8b [2] 8e 87 [2] 82 8d [2] 95 86 [2] 8e c8 [2] b3 }

  condition:
    any of them
}