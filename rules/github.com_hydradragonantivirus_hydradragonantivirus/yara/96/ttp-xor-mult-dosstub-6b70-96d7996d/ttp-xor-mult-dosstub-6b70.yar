rule TTP_XOR_MULT_DOSStub_6b70 {
  strings:
    $key_6b70 = { 3f 18 [2] 4b 00 [2] 0c 02 [2] 4b 13 [2] 05 1f [2] 09 15 [2] 1e 1e [2] 05 50 [2] 38 }

  condition:
    any of them
}