rule TTP_XOR_MULT_DOSStub_e748 {
  strings:
    $key_e748 = { b3 20 [2] c7 38 [2] 80 3a [2] c7 2b [2] 89 27 [2] 85 2d [2] 92 26 [2] 89 68 [2] b4 }

  condition:
    any of them
}