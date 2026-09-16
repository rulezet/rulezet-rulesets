rule TTP_XOR_MULT_DOSStub_7067 {
  strings:
    $key_7067 = { 24 0f [2] 50 17 [2] 17 15 [2] 50 04 [2] 1e 08 [2] 12 02 [2] 05 09 [2] 1e 47 [2] 23 }

  condition:
    any of them
}