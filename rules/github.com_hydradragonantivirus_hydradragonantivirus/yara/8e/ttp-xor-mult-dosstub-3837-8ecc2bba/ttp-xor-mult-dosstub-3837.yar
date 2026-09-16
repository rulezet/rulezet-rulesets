rule TTP_XOR_MULT_DOSStub_3837 {
  strings:
    $key_3837 = { 6c 5f [2] 18 47 [2] 5f 45 [2] 18 54 [2] 56 58 [2] 5a 52 [2] 4d 59 [2] 56 17 [2] 6b }

  condition:
    any of them
}