rule TTP_XOR_MULT_DOSStub_e209 {
  strings:
    $key_e209 = { b6 61 [2] c2 79 [2] 85 7b [2] c2 6a [2] 8c 66 [2] 80 6c [2] 97 67 [2] 8c 29 [2] b1 }

  condition:
    any of them
}