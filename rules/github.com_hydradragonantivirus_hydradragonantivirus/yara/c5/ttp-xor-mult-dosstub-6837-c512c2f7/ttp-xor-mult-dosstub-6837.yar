rule TTP_XOR_MULT_DOSStub_6837 {
  strings:
    $key_6837 = { 3c 5f [2] 48 47 [2] 0f 45 [2] 48 54 [2] 06 58 [2] 0a 52 [2] 1d 59 [2] 06 17 [2] 3b }

  condition:
    any of them
}