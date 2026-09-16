rule TTP_XOR_MULT_DOSStub_6590 {
  strings:
    $key_6590 = { 31 f8 [2] 45 e0 [2] 02 e2 [2] 45 f3 [2] 0b ff [2] 07 f5 [2] 10 fe [2] 0b b0 [2] 36 }

  condition:
    any of them
}