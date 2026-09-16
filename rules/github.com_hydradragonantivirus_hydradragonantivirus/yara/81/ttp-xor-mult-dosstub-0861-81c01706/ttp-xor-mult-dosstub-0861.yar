rule TTP_XOR_MULT_DOSStub_0861 {
  strings:
    $key_0861 = { 5c 09 [2] 28 11 [2] 6f 13 [2] 28 02 [2] 66 0e [2] 6a 04 [2] 7d 0f [2] 66 41 [2] 5b }

  condition:
    any of them
}