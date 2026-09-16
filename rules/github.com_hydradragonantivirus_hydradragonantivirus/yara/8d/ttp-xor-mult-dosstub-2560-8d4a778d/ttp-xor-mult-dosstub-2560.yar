rule TTP_XOR_MULT_DOSStub_2560 {
  strings:
    $key_2560 = { 71 08 [2] 05 10 [2] 42 12 [2] 05 03 [2] 4b 0f [2] 47 05 [2] 50 0e [2] 4b 40 [2] 76 }

  condition:
    any of them
}