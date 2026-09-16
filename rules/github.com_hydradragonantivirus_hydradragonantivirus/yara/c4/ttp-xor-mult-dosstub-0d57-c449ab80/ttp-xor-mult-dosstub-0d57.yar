rule TTP_XOR_MULT_DOSStub_0d57 {
  strings:
    $key_0d57 = { 59 3f [2] 2d 27 [2] 6a 25 [2] 2d 34 [2] 63 38 [2] 6f 32 [2] 78 39 [2] 63 77 [2] 5e }

  condition:
    any of them
}