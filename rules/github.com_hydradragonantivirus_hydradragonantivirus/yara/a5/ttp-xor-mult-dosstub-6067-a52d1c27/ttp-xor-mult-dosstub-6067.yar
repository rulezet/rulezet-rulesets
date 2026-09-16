rule TTP_XOR_MULT_DOSStub_6067 {
  strings:
    $key_6067 = { 34 0f [2] 40 17 [2] 07 15 [2] 40 04 [2] 0e 08 [2] 02 02 [2] 15 09 [2] 0e 47 [2] 33 }

  condition:
    any of them
}