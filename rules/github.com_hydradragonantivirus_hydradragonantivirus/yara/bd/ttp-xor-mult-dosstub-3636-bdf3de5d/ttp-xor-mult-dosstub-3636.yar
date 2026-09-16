rule TTP_XOR_MULT_DOSStub_3636 {
  strings:
    $key_3636 = { 62 5e [2] 16 46 [2] 51 44 [2] 16 55 [2] 58 59 [2] 54 53 [2] 43 58 [2] 58 16 [2] 65 }

  condition:
    any of them
}