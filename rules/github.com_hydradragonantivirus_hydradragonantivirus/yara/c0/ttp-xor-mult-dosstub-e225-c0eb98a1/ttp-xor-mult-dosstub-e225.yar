rule TTP_XOR_MULT_DOSStub_e225 {
  strings:
    $key_e225 = { b6 4d [2] c2 55 [2] 85 57 [2] c2 46 [2] 8c 4a [2] 80 40 [2] 97 4b [2] 8c 05 [2] b1 }

  condition:
    any of them
}