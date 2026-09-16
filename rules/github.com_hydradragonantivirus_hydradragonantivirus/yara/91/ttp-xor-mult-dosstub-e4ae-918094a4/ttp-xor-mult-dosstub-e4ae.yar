rule TTP_XOR_MULT_DOSStub_e4ae {
  strings:
    $key_e4ae = { b0 c6 [2] c4 de [2] 83 dc [2] c4 cd [2] 8a c1 [2] 86 cb [2] 91 c0 [2] 8a 8e [2] b7 }

  condition:
    any of them
}