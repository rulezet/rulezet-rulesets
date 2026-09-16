rule TTP_XOR_MULT_DOSStub_3367 {
  strings:
    $key_3367 = { 67 0f [2] 13 17 [2] 54 15 [2] 13 04 [2] 5d 08 [2] 51 02 [2] 46 09 [2] 5d 47 [2] 60 }

  condition:
    any of them
}