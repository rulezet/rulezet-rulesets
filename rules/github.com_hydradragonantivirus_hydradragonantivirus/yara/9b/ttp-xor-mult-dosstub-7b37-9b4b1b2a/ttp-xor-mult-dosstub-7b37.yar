rule TTP_XOR_MULT_DOSStub_7b37 {
  strings:
    $key_7b37 = { 2f 5f [2] 5b 47 [2] 1c 45 [2] 5b 54 [2] 15 58 [2] 19 52 [2] 0e 59 [2] 15 17 [2] 28 }

  condition:
    any of them
}