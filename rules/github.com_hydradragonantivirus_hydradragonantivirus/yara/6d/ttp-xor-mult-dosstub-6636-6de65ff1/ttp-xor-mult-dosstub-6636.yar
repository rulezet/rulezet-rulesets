rule TTP_XOR_MULT_DOSStub_6636 {
  strings:
    $key_6636 = { 32 5e [2] 46 46 [2] 01 44 [2] 46 55 [2] 08 59 [2] 04 53 [2] 13 58 [2] 08 16 [2] 35 }

  condition:
    any of them
}