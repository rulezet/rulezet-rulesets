rule TTP_XOR_MULT_DOSStub_6d70 {
  strings:
    $key_6d70 = { 39 18 [2] 4d 00 [2] 0a 02 [2] 4d 13 [2] 03 1f [2] 0f 15 [2] 18 1e [2] 03 50 [2] 3e }

  condition:
    any of them
}