rule TTP_XOR_MULT_DOSStub_2267 {
  strings:
    $key_2267 = { 76 0f [2] 02 17 [2] 45 15 [2] 02 04 [2] 4c 08 [2] 40 02 [2] 57 09 [2] 4c 47 [2] 71 }

  condition:
    any of them
}