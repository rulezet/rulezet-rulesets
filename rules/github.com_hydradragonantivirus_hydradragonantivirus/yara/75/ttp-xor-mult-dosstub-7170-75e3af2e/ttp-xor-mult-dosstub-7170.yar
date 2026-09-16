rule TTP_XOR_MULT_DOSStub_7170 {
  strings:
    $key_7170 = { 25 18 [2] 51 00 [2] 16 02 [2] 51 13 [2] 1f 1f [2] 13 15 [2] 04 1e [2] 1f 50 [2] 22 }

  condition:
    any of them
}