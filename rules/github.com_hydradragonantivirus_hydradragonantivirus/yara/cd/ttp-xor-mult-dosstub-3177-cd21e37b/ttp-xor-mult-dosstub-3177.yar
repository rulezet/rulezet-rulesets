rule TTP_XOR_MULT_DOSStub_3177 {
  strings:
    $key_3177 = { 65 1f [2] 11 07 [2] 56 05 [2] 11 14 [2] 5f 18 [2] 53 12 [2] 44 19 [2] 5f 57 [2] 62 }

  condition:
    any of them
}