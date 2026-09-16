rule TTP_XOR_MULT_DOSStub_3b50 {
  strings:
    $key_3b50 = { 6f 38 [2] 1b 20 [2] 5c 22 [2] 1b 33 [2] 55 3f [2] 59 35 [2] 4e 3e [2] 55 70 [2] 68 }

  condition:
    any of them
}