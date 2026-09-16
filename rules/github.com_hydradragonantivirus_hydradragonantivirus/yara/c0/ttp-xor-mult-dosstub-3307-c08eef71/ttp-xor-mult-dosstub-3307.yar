rule TTP_XOR_MULT_DOSStub_3307 {
  strings:
    $key_3307 = { 67 6f [2] 13 77 [2] 54 75 [2] 13 64 [2] 5d 68 [2] 51 62 [2] 46 69 [2] 5d 27 [2] 60 }

  condition:
    any of them
}