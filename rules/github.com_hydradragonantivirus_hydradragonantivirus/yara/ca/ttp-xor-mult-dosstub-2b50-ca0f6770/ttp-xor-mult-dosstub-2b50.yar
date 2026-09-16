rule TTP_XOR_MULT_DOSStub_2b50 {
  strings:
    $key_2b50 = { 7f 38 [2] 0b 20 [2] 4c 22 [2] 0b 33 [2] 45 3f [2] 49 35 [2] 5e 3e [2] 45 70 [2] 78 }

  condition:
    any of them
}