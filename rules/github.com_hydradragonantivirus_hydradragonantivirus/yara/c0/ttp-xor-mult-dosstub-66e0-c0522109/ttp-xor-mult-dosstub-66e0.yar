rule TTP_XOR_MULT_DOSStub_66e0 {
  strings:
    $key_66e0 = { 32 88 [2] 46 90 [2] 01 92 [2] 46 83 [2] 08 8f [2] 04 85 [2] 13 8e [2] 08 c0 [2] 35 }

  condition:
    any of them
}