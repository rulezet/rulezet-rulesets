rule TTP_XOR_MULT_DOSStub_3520 {
  strings:
    $key_3520 = { 61 48 [2] 15 50 [2] 52 52 [2] 15 43 [2] 5b 4f [2] 57 45 [2] 40 4e [2] 5b 00 [2] 66 }

  condition:
    any of them
}