rule TTP_XOR_MULT_DOSStub_5161 {
  strings:
    $key_5161 = { 05 09 [2] 71 11 [2] 36 13 [2] 71 02 [2] 3f 0e [2] 33 04 [2] 24 0f [2] 3f 41 [2] 02 }

  condition:
    any of them
}