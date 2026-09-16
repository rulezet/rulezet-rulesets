rule TTP_XOR_MULT_DOSStub_4137 {
  strings:
    $key_4137 = { 15 5f [2] 61 47 [2] 26 45 [2] 61 54 [2] 2f 58 [2] 23 52 [2] 34 59 [2] 2f 17 [2] 12 }

  condition:
    any of them
}