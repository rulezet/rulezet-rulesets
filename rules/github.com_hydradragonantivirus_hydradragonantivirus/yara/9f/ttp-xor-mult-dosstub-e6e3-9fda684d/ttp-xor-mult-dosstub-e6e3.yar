rule TTP_XOR_MULT_DOSStub_e6e3 {
  strings:
    $key_e6e3 = { b2 8b [2] c6 93 [2] 81 91 [2] c6 80 [2] 88 8c [2] 84 86 [2] 93 8d [2] 88 c3 [2] b5 }

  condition:
    any of them
}