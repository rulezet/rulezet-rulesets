rule TTP_XOR_MULT_DOSStub_c984 {
  strings:
    $key_c984 = { 9d ec [2] e9 f4 [2] ae f6 [2] e9 e7 [2] a7 eb [2] ab e1 [2] bc ea [2] a7 a4 [2] 9a }

  condition:
    any of them
}