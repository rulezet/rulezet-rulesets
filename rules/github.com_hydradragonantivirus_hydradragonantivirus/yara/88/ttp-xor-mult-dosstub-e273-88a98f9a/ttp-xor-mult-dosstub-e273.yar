rule TTP_XOR_MULT_DOSStub_e273 {
  strings:
    $key_e273 = { b6 1b [2] c2 03 [2] 85 01 [2] c2 10 [2] 8c 1c [2] 80 16 [2] 97 1d [2] 8c 53 [2] b1 }

  condition:
    any of them
}