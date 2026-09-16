rule TTP_XOR_MULT_DOSStub_e709 {
  strings:
    $key_e709 = { b3 61 [2] c7 79 [2] 80 7b [2] c7 6a [2] 89 66 [2] 85 6c [2] 92 67 [2] 89 29 [2] b4 }

  condition:
    any of them
}