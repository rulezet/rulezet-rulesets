rule TTP_XOR_MULT_DOSStub_6867 {
  strings:
    $key_6867 = { 3c 0f [2] 48 17 [2] 0f 15 [2] 48 04 [2] 06 08 [2] 0a 02 [2] 1d 09 [2] 06 47 [2] 3b }

  condition:
    any of them
}