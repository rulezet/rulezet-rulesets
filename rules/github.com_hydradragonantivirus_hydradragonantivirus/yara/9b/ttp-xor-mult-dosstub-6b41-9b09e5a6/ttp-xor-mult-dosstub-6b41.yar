rule TTP_XOR_MULT_DOSStub_6b41 {
  strings:
    $key_6b41 = { 3f 29 [2] 4b 31 [2] 0c 33 [2] 4b 22 [2] 05 2e [2] 09 24 [2] 1e 2f [2] 05 61 [2] 38 }

  condition:
    any of them
}