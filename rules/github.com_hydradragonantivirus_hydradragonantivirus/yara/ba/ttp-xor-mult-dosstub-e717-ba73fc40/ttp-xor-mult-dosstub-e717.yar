rule TTP_XOR_MULT_DOSStub_e717 {
  strings:
    $key_e717 = { b3 7f [2] c7 67 [2] 80 65 [2] c7 74 [2] 89 78 [2] 85 72 [2] 92 79 [2] 89 37 [2] b4 }

  condition:
    any of them
}