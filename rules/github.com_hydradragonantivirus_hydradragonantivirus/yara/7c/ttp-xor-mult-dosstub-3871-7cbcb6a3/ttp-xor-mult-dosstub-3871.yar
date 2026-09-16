rule TTP_XOR_MULT_DOSStub_3871 {
  strings:
    $key_3871 = { 6c 19 [2] 18 01 [2] 5f 03 [2] 18 12 [2] 56 1e [2] 5a 14 [2] 4d 1f [2] 56 51 [2] 6b }

  condition:
    any of them
}