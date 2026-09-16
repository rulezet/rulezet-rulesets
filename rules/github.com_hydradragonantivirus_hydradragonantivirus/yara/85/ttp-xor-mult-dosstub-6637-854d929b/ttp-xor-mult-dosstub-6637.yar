rule TTP_XOR_MULT_DOSStub_6637 {
  strings:
    $key_6637 = { 32 5f [2] 46 47 [2] 01 45 [2] 46 54 [2] 08 58 [2] 04 52 [2] 13 59 [2] 08 17 [2] 35 }

  condition:
    any of them
}