rule TTP_XOR_MULT_DOSStub_36e1 {
  strings:
    $key_36e1 = { 62 89 [2] 16 91 [2] 51 93 [2] 16 82 [2] 58 8e [2] 54 84 [2] 43 8f [2] 58 c1 [2] 65 }

  condition:
    any of them
}