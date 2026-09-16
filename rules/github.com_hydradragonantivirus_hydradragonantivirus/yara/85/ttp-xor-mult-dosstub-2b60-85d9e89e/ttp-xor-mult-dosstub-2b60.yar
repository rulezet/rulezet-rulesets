rule TTP_XOR_MULT_DOSStub_2b60 {
  strings:
    $key_2b60 = { 7f 08 [2] 0b 10 [2] 4c 12 [2] 0b 03 [2] 45 0f [2] 49 05 [2] 5e 0e [2] 45 40 [2] 78 }

  condition:
    any of them
}