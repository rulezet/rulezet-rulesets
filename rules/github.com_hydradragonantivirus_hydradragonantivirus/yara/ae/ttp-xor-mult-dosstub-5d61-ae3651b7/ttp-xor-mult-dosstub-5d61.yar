rule TTP_XOR_MULT_DOSStub_5d61 {
  strings:
    $key_5d61 = { 09 09 [2] 7d 11 [2] 3a 13 [2] 7d 02 [2] 33 0e [2] 3f 04 [2] 28 0f [2] 33 41 [2] 0e }

  condition:
    any of them
}