rule TTP_XOR_MULT_DOSStub_3876 {
  strings:
    $key_3876 = { 6c 1e [2] 18 06 [2] 5f 04 [2] 18 15 [2] 56 19 [2] 5a 13 [2] 4d 18 [2] 56 56 [2] 6b }

  condition:
    any of them
}