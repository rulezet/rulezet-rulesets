rule TTP_XOR_MULT_DOSStub_e410 {
  strings:
    $key_e410 = { b0 78 [2] c4 60 [2] 83 62 [2] c4 73 [2] 8a 7f [2] 86 75 [2] 91 7e [2] 8a 30 [2] b7 }

  condition:
    any of them
}