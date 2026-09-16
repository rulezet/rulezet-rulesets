rule TTP_XOR_MULT_DOSStub_0557 {
  strings:
    $key_0557 = { 51 3f [2] 25 27 [2] 62 25 [2] 25 34 [2] 6b 38 [2] 67 32 [2] 70 39 [2] 6b 77 [2] 56 }

  condition:
    any of them
}