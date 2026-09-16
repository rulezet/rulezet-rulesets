rule TTP_XOR_MULT_DOSStub_6b76 {
  strings:
    $key_6b76 = { 3f 1e [2] 4b 06 [2] 0c 04 [2] 4b 15 [2] 05 19 [2] 09 13 [2] 1e 18 [2] 05 56 [2] 38 }

  condition:
    any of them
}