rule TTP_XOR_MULT_DOSStub_3861 {
  strings:
    $key_3861 = { 6c 09 [2] 18 11 [2] 5f 13 [2] 18 02 [2] 56 0e [2] 5a 04 [2] 4d 0f [2] 56 41 [2] 6b }

  condition:
    any of them
}