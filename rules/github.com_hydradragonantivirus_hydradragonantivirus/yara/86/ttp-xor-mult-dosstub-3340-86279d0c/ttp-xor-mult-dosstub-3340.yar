rule TTP_XOR_MULT_DOSStub_3340 {
  strings:
    $key_3340 = { 67 28 [2] 13 30 [2] 54 32 [2] 13 23 [2] 5d 2f [2] 51 25 [2] 46 2e [2] 5d 60 [2] 60 }

  condition:
    any of them
}