rule TTP_XOR_MULT_DOSStub_e725 {
  strings:
    $key_e725 = { b3 4d [2] c7 55 [2] 80 57 [2] c7 46 [2] 89 4a [2] 85 40 [2] 92 4b [2] 89 05 [2] b4 }

  condition:
    any of them
}