rule TTP_XOR_MULT_DOSStub_e76d {
  strings:
    $key_e76d = { b3 05 [2] c7 1d [2] 80 1f [2] c7 0e [2] 89 02 [2] 85 08 [2] 92 03 [2] 89 4d [2] b4 }

  condition:
    any of them
}