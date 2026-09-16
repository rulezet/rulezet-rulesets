rule TTP_XOR_MULT_DOSStub_2117 {
  strings:
    $key_2117 = { 75 7f [2] 01 67 [2] 46 65 [2] 01 74 [2] 4f 78 [2] 43 72 [2] 54 79 [2] 4f 37 [2] 72 }

  condition:
    any of them
}