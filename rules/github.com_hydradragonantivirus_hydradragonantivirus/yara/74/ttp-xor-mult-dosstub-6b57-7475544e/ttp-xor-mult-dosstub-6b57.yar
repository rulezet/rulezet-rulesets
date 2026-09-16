rule TTP_XOR_MULT_DOSStub_6b57 {
  strings:
    $key_6b57 = { 3f 3f [2] 4b 27 [2] 0c 25 [2] 4b 34 [2] 05 38 [2] 09 32 [2] 1e 39 [2] 05 77 [2] 38 }

  condition:
    any of them
}