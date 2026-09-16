rule TTP_XOR_MULT_DOSStub_3860 {
  strings:
    $key_3860 = { 6c 08 [2] 18 10 [2] 5f 12 [2] 18 03 [2] 56 0f [2] 5a 05 [2] 4d 0e [2] 56 40 [2] 6b }

  condition:
    any of them
}