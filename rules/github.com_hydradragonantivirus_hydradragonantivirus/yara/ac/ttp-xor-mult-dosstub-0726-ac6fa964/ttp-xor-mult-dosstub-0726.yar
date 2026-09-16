rule TTP_XOR_MULT_DOSStub_0726 {
  strings:
    $key_0726 = { 53 4e [2] 27 56 [2] 60 54 [2] 27 45 [2] 69 49 [2] 65 43 [2] 72 48 [2] 69 06 [2] 54 }

  condition:
    any of them
}