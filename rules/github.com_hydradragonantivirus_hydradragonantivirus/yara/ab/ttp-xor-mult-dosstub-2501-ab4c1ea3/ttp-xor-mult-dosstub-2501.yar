rule TTP_XOR_MULT_DOSStub_2501 {
  strings:
    $key_2501 = { 71 69 [2] 05 71 [2] 42 73 [2] 05 62 [2] 4b 6e [2] 47 64 [2] 50 6f [2] 4b 21 [2] 76 }

  condition:
    any of them
}