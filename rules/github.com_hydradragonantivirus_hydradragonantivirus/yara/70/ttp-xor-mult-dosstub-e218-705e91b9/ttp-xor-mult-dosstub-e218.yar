rule TTP_XOR_MULT_DOSStub_e218 {
  strings:
    $key_e218 = { b6 70 [2] c2 68 [2] 85 6a [2] c2 7b [2] 8c 77 [2] 80 7d [2] 97 76 [2] 8c 38 [2] b1 }

  condition:
    any of them
}