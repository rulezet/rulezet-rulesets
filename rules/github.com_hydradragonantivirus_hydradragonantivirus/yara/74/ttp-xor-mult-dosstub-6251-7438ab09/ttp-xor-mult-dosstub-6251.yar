rule TTP_XOR_MULT_DOSStub_6251 {
  strings:
    $key_6251 = { 36 39 [2] 42 21 [2] 05 23 [2] 42 32 [2] 0c 3e [2] 00 34 [2] 17 3f [2] 0c 71 [2] 31 }

  condition:
    any of them
}