rule TTP_XOR_MULT_DOSStub_e40a {
  strings:
    $key_e40a = { b0 62 [2] c4 7a [2] 83 78 [2] c4 69 [2] 8a 65 [2] 86 6f [2] 91 64 [2] 8a 2a [2] b7 }

  condition:
    any of them
}