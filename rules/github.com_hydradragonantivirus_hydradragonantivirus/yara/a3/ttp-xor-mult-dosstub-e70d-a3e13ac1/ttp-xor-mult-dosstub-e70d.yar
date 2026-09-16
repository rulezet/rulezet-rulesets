rule TTP_XOR_MULT_DOSStub_e70d {
  strings:
    $key_e70d = { b3 65 [2] c7 7d [2] 80 7f [2] c7 6e [2] 89 62 [2] 85 68 [2] 92 63 [2] 89 2d [2] b4 }

  condition:
    any of them
}