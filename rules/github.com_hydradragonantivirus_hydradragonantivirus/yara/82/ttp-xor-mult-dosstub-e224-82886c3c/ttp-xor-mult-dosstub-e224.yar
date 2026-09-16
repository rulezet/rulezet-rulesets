rule TTP_XOR_MULT_DOSStub_e224 {
  strings:
    $key_e224 = { b6 4c [2] c2 54 [2] 85 56 [2] c2 47 [2] 8c 4b [2] 80 41 [2] 97 4a [2] 8c 04 [2] b1 }

  condition:
    any of them
}