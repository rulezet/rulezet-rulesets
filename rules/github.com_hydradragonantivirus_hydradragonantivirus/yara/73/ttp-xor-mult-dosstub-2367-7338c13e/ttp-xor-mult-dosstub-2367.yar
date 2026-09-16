rule TTP_XOR_MULT_DOSStub_2367 {
  strings:
    $key_2367 = { 77 0f [2] 03 17 [2] 44 15 [2] 03 04 [2] 4d 08 [2] 41 02 [2] 56 09 [2] 4d 47 [2] 70 }

  condition:
    any of them
}