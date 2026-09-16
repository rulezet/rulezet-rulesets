rule TTP_XOR_MULT_DOSStub_3067 {
  strings:
    $key_3067 = { 64 0f [2] 10 17 [2] 57 15 [2] 10 04 [2] 5e 08 [2] 52 02 [2] 45 09 [2] 5e 47 [2] 63 }

  condition:
    any of them
}