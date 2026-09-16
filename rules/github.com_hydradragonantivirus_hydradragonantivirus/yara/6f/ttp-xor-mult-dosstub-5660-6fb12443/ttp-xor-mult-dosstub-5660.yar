rule TTP_XOR_MULT_DOSStub_5660 {
  strings:
    $key_5660 = { 02 08 [2] 76 10 [2] 31 12 [2] 76 03 [2] 38 0f [2] 34 05 [2] 23 0e [2] 38 40 [2] 05 }

  condition:
    any of them
}