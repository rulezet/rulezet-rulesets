rule TTP_XOR_MULT_DOSStub_3077 {
  strings:
    $key_3077 = { 64 1f [2] 10 07 [2] 57 05 [2] 10 14 [2] 5e 18 [2] 52 12 [2] 45 19 [2] 5e 57 [2] 63 }

  condition:
    any of them
}