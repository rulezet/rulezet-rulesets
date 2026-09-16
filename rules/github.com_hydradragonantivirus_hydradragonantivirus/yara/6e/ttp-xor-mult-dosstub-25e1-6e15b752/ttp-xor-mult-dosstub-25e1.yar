rule TTP_XOR_MULT_DOSStub_25e1 {
  strings:
    $key_25e1 = { 71 89 [2] 05 91 [2] 42 93 [2] 05 82 [2] 4b 8e [2] 47 84 [2] 50 8f [2] 4b c1 [2] 76 }

  condition:
    any of them
}