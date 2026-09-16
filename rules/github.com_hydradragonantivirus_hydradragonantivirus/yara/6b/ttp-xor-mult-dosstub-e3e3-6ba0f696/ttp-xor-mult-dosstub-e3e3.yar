rule TTP_XOR_MULT_DOSStub_e3e3 {
  strings:
    $key_e3e3 = { b7 8b [2] c3 93 [2] 84 91 [2] c3 80 [2] 8d 8c [2] 81 86 [2] 96 8d [2] 8d c3 [2] b0 }

  condition:
    any of them
}