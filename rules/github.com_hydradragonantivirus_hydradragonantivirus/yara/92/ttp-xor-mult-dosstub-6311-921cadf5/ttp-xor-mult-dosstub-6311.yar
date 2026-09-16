rule TTP_XOR_MULT_DOSStub_6311 {
  strings:
    $key_6311 = { 37 79 [2] 43 61 [2] 04 63 [2] 43 72 [2] 0d 7e [2] 01 74 [2] 16 7f [2] 0d 31 [2] 30 }

  condition:
    any of them
}