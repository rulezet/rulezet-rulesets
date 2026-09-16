rule TTP_XOR_MULT_DOSStub_2750 {
  strings:
    $key_2750 = { 73 38 [2] 07 20 [2] 40 22 [2] 07 33 [2] 49 3f [2] 45 35 [2] 52 3e [2] 49 70 [2] 74 }

  condition:
    any of them
}