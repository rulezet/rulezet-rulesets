rule TTP_XOR_MULT_DOSStub_0d21 {
  strings:
    $key_0d21 = { 59 49 [2] 2d 51 [2] 6a 53 [2] 2d 42 [2] 63 4e [2] 6f 44 [2] 78 4f [2] 63 01 [2] 5e }

  condition:
    any of them
}