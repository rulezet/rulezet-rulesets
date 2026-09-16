rule TTP_XOR_MULT_DOSStub_6b36 {
  strings:
    $key_6b36 = { 3f 5e [2] 4b 46 [2] 0c 44 [2] 4b 55 [2] 05 59 [2] 09 53 [2] 1e 58 [2] 05 16 [2] 38 }

  condition:
    any of them
}