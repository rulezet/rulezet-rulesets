rule TTP_XOR_MULT_DOSStub_1330 {
  strings:
    $key_1330 = { 47 58 [2] 33 40 [2] 74 42 [2] 33 53 [2] 7d 5f [2] 71 55 [2] 66 5e [2] 7d 10 [2] 40 }

  condition:
    any of them
}