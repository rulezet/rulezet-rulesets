rule TTP_XOR_MULT_DOSStub_e7e8 {
  strings:
    $key_e7e8 = { b3 80 [2] c7 98 [2] 80 9a [2] c7 8b [2] 89 87 [2] 85 8d [2] 92 86 [2] 89 c8 [2] b4 }

  condition:
    any of them
}