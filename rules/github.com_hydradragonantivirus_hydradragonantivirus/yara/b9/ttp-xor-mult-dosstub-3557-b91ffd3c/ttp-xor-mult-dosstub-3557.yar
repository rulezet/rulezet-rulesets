rule TTP_XOR_MULT_DOSStub_3557 {
  strings:
    $key_3557 = { 61 3f [2] 15 27 [2] 52 25 [2] 15 34 [2] 5b 38 [2] 57 32 [2] 40 39 [2] 5b 77 [2] 66 }

  condition:
    any of them
}