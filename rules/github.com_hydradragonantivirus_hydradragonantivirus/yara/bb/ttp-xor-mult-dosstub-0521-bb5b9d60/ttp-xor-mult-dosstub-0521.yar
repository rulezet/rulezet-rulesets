rule TTP_XOR_MULT_DOSStub_0521 {
  strings:
    $key_0521 = { 51 49 [2] 25 51 [2] 62 53 [2] 25 42 [2] 6b 4e [2] 67 44 [2] 70 4f [2] 6b 01 [2] 56 }

  condition:
    any of them
}