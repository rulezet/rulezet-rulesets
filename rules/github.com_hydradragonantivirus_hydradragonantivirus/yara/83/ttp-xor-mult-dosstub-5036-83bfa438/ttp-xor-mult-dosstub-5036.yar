rule TTP_XOR_MULT_DOSStub_5036 {
  strings:
    $key_5036 = { 04 5e [2] 70 46 [2] 37 44 [2] 70 55 [2] 3e 59 [2] 32 53 [2] 25 58 [2] 3e 16 [2] 03 }

  condition:
    any of them
}