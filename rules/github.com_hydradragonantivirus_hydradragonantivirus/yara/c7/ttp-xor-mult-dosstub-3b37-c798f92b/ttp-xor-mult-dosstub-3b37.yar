rule TTP_XOR_MULT_DOSStub_3b37 {
  strings:
    $key_3b37 = { 6f 5f [2] 1b 47 [2] 5c 45 [2] 1b 54 [2] 55 58 [2] 59 52 [2] 4e 59 [2] 55 17 [2] 68 }

  condition:
    any of them
}