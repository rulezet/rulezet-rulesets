rule TTP_XOR_MULT_DOSStub_3260 {
  strings:
    $key_3260 = { 66 08 [2] 12 10 [2] 55 12 [2] 12 03 [2] 5c 0f [2] 50 05 [2] 47 0e [2] 5c 40 [2] 61 }

  condition:
    any of them
}