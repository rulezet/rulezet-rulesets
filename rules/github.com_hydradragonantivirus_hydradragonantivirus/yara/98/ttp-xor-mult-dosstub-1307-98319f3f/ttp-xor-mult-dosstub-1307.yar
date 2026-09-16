rule TTP_XOR_MULT_DOSStub_1307 {
  strings:
    $key_1307 = { 47 6f [2] 33 77 [2] 74 75 [2] 33 64 [2] 7d 68 [2] 71 62 [2] 66 69 [2] 7d 27 [2] 40 }

  condition:
    any of them
}