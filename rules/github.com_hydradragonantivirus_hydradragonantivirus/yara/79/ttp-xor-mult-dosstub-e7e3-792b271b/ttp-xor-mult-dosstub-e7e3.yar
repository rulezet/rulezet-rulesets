rule TTP_XOR_MULT_DOSStub_e7e3 {
  strings:
    $key_e7e3 = { b3 8b [2] c7 93 [2] 80 91 [2] c7 80 [2] 89 8c [2] 85 86 [2] 92 8d [2] 89 c3 [2] b4 }

  condition:
    any of them
}