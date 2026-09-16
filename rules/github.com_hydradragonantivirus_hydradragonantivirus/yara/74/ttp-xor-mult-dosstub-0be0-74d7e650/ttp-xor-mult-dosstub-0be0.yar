rule TTP_XOR_MULT_DOSStub_0be0 {
  strings:
    $key_0be0 = { 5f 88 [2] 2b 90 [2] 6c 92 [2] 2b 83 [2] 65 8f [2] 69 85 [2] 7e 8e [2] 65 c0 [2] 58 }

  condition:
    any of them
}