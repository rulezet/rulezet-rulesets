rule TTP_XOR_MULT_DOSStub_0767 {
  strings:
    $key_0767 = { 53 0f [2] 27 17 [2] 60 15 [2] 27 04 [2] 69 08 [2] 65 02 [2] 72 09 [2] 69 47 [2] 54 }

  condition:
    any of them
}