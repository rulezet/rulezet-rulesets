rule TTP_XOR_MULT_DOSStub_6557 {
  strings:
    $key_6557 = { 31 3f [2] 45 27 [2] 02 25 [2] 45 34 [2] 0b 38 [2] 07 32 [2] 10 39 [2] 0b 77 [2] 36 }

  condition:
    any of them
}