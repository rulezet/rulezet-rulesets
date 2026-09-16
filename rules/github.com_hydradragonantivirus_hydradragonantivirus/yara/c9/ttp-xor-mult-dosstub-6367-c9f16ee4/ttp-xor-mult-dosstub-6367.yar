rule TTP_XOR_MULT_DOSStub_6367 {
  strings:
    $key_6367 = { 37 0f [2] 43 17 [2] 04 15 [2] 43 04 [2] 0d 08 [2] 01 02 [2] 16 09 [2] 0d 47 [2] 30 }

  condition:
    any of them
}