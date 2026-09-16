rule TTP_XOR_MULT_DOSStub_6b61 {
  strings:
    $key_6b61 = { 3f 09 [2] 4b 11 [2] 0c 13 [2] 4b 02 [2] 05 0e [2] 09 04 [2] 1e 0f [2] 05 41 [2] 38 }

  condition:
    any of them
}