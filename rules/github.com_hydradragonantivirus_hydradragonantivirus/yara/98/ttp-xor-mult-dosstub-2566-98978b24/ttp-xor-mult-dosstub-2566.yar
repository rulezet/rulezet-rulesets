rule TTP_XOR_MULT_DOSStub_2566 {
  strings:
    $key_2566 = { 71 0e [2] 05 16 [2] 42 14 [2] 05 05 [2] 4b 09 [2] 47 03 [2] 50 08 [2] 4b 46 [2] 76 }

  condition:
    any of them
}