rule TTP_XOR_MULT_DOSStub_3867 {
  strings:
    $key_3867 = { 6c 0f [2] 18 17 [2] 5f 15 [2] 18 04 [2] 56 08 [2] 5a 02 [2] 4d 09 [2] 56 47 [2] 6b }

  condition:
    any of them
}