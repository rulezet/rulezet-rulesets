rule TTP_XOR_MULT_DOSStub_0511 {
  strings:
    $key_0511 = { 51 79 [2] 25 61 [2] 62 63 [2] 25 72 [2] 6b 7e [2] 67 74 [2] 70 7f [2] 6b 31 [2] 56 }

  condition:
    any of them
}