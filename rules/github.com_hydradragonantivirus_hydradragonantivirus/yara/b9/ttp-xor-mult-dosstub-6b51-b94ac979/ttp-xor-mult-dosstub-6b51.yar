rule TTP_XOR_MULT_DOSStub_6b51 {
  strings:
    $key_6b51 = { 3f 39 [2] 4b 21 [2] 0c 23 [2] 4b 32 [2] 05 3e [2] 09 34 [2] 1e 3f [2] 05 71 [2] 38 }

  condition:
    any of them
}