rule TTP_XOR_MULT_DOSStub_2760 {
  strings:
    $key_2760 = { 73 08 [2] 07 10 [2] 40 12 [2] 07 03 [2] 49 0f [2] 45 05 [2] 52 0e [2] 49 40 [2] 74 }

  condition:
    any of them
}