rule TTP_XOR_MULT_DOSStub_e50d {
  strings:
    $key_e50d = { b1 65 [2] c5 7d [2] 82 7f [2] c5 6e [2] 8b 62 [2] 87 68 [2] 90 63 [2] 8b 2d [2] b6 }

  condition:
    any of them
}