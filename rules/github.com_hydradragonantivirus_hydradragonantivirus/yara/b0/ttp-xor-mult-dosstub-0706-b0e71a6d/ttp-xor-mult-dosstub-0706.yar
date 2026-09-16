rule TTP_XOR_MULT_DOSStub_0706 {
  strings:
    $key_0706 = { 53 6e [2] 27 76 [2] 60 74 [2] 27 65 [2] 69 69 [2] 65 63 [2] 72 68 [2] 69 26 [2] 54 }

  condition:
    any of them
}