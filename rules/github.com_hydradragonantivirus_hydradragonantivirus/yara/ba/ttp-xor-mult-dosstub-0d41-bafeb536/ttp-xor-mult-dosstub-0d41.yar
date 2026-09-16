rule TTP_XOR_MULT_DOSStub_0d41 {
  strings:
    $key_0d41 = { 59 29 [2] 2d 31 [2] 6a 33 [2] 2d 22 [2] 63 2e [2] 6f 24 [2] 78 2f [2] 63 61 [2] 5e }

  condition:
    any of them
}