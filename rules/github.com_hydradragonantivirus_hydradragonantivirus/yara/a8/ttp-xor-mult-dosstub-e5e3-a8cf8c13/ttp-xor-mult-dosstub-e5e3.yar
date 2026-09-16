rule TTP_XOR_MULT_DOSStub_e5e3 {
  strings:
    $key_e5e3 = { b1 8b [2] c5 93 [2] 82 91 [2] c5 80 [2] 8b 8c [2] 87 86 [2] 90 8d [2] 8b c3 [2] b6 }

  condition:
    any of them
}