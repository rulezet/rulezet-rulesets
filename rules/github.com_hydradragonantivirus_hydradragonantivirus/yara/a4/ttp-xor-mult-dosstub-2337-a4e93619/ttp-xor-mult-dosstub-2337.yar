rule TTP_XOR_MULT_DOSStub_2337 {
  strings:
    $key_2337 = { 77 5f [2] 03 47 [2] 44 45 [2] 03 54 [2] 4d 58 [2] 41 52 [2] 56 59 [2] 4d 17 [2] 70 }

  condition:
    any of them
}