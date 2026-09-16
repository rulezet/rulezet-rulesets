rule TTP_XOR_MULT_DOSStub_2146 {
  strings:
    $key_2146 = { 75 2e [2] 01 36 [2] 46 34 [2] 01 25 [2] 4f 29 [2] 43 23 [2] 54 28 [2] 4f 66 [2] 72 }

  condition:
    any of them
}