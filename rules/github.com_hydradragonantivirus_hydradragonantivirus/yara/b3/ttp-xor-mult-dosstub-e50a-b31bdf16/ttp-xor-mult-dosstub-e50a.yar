rule TTP_XOR_MULT_DOSStub_e50a {
  strings:
    $key_e50a = { b1 62 [2] c5 7a [2] 82 78 [2] c5 69 [2] 8b 65 [2] 87 6f [2] 90 64 [2] 8b 2a [2] b6 }

  condition:
    any of them
}