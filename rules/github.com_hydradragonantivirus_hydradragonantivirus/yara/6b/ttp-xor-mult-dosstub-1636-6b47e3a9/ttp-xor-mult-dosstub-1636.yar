rule TTP_XOR_MULT_DOSStub_1636 {
  strings:
    $key_1636 = { 42 5e [2] 36 46 [2] 71 44 [2] 36 55 [2] 78 59 [2] 74 53 [2] 63 58 [2] 78 16 [2] 45 }

  condition:
    any of them
}