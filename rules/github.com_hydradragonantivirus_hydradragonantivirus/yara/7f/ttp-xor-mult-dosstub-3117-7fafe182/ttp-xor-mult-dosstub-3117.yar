rule TTP_XOR_MULT_DOSStub_3117 {
  strings:
    $key_3117 = { 65 7f [2] 11 67 [2] 56 65 [2] 11 74 [2] 5f 78 [2] 53 72 [2] 44 79 [2] 5f 37 [2] 62 }

  condition:
    any of them
}