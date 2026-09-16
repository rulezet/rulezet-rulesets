rule TTP_XOR_MULT_DOSStub_5077 {
  strings:
    $key_5077 = { 04 1f [2] 70 07 [2] 37 05 [2] 70 14 [2] 3e 18 [2] 32 12 [2] 25 19 [2] 3e 57 [2] 03 }

  condition:
    any of them
}