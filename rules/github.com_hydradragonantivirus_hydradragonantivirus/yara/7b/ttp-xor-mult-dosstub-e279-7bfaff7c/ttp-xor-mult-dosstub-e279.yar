rule TTP_XOR_MULT_DOSStub_e279 {
  strings:
    $key_e279 = { b6 11 [2] c2 09 [2] 85 0b [2] c2 1a [2] 8c 16 [2] 80 1c [2] 97 17 [2] 8c 59 [2] b1 }

  condition:
    any of them
}