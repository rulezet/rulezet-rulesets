rule TTP_XOR_MULT_DOSStub_0b37 {
  strings:
    $key_0b37 = { 5f 5f [2] 2b 47 [2] 6c 45 [2] 2b 54 [2] 65 58 [2] 69 52 [2] 7e 59 [2] 65 17 [2] 58 }

  condition:
    any of them
}