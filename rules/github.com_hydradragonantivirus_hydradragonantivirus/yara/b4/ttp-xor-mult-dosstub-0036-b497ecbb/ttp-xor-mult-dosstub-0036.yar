rule TTP_XOR_MULT_DOSStub_0036 {
  strings:
    $key_0036 = { 54 5e [2] 20 46 [2] 67 44 [2] 20 55 [2] 6e 59 [2] 62 53 [2] 75 58 [2] 6e 16 [2] 53 }

  condition:
    any of them
}