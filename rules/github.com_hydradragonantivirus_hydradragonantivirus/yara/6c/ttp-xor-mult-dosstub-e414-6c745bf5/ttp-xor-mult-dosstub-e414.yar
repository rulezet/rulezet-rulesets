rule TTP_XOR_MULT_DOSStub_e414 {
  strings:
    $key_e414 = { b0 7c [2] c4 64 [2] 83 66 [2] c4 77 [2] 8a 7b [2] 86 71 [2] 91 7a [2] 8a 34 [2] b7 }

  condition:
    any of them
}