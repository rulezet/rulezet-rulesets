rule TTP_XOR_MULT_DOSStub_0d60 {
  strings:
    $key_0d60 = { 59 08 [2] 2d 10 [2] 6a 12 [2] 2d 03 [2] 63 0f [2] 6f 05 [2] 78 0e [2] 63 40 [2] 5e }

  condition:
    any of them
}