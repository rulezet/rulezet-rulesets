rule TTP_XOR_MULT_DOSStub_0867 {
  strings:
    $key_0867 = { 5c 0f [2] 28 17 [2] 6f 15 [2] 28 04 [2] 66 08 [2] 6a 02 [2] 7d 09 [2] 66 47 [2] 5b }

  condition:
    any of them
}