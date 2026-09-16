rule TTP_XOR_MULT_DOSStub_2747 {
  strings:
    $key_2747 = { 73 2f [2] 07 37 [2] 40 35 [2] 07 24 [2] 49 28 [2] 45 22 [2] 52 29 [2] 49 67 [2] 74 }

  condition:
    any of them
}