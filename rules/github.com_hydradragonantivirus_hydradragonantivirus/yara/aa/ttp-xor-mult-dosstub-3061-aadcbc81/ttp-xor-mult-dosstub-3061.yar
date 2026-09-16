rule TTP_XOR_MULT_DOSStub_3061 {
  strings:
    $key_3061 = { 64 09 [2] 10 11 [2] 57 13 [2] 10 02 [2] 5e 0e [2] 52 04 [2] 45 0f [2] 5e 41 [2] 63 }

  condition:
    any of them
}