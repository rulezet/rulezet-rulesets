rule TTP_XOR_MULT_DOSStub_3351 {
  strings:
    $key_3351 = { 67 39 [2] 13 21 [2] 54 23 [2] 13 32 [2] 5d 3e [2] 51 34 [2] 46 3f [2] 5d 71 [2] 60 }

  condition:
    any of them
}