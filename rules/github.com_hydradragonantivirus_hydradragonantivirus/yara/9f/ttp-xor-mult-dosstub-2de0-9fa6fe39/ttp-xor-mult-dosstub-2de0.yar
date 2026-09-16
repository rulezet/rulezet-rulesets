rule TTP_XOR_MULT_DOSStub_2de0 {
  strings:
    $key_2de0 = { 79 88 [2] 0d 90 [2] 4a 92 [2] 0d 83 [2] 43 8f [2] 4f 85 [2] 58 8e [2] 43 c0 [2] 7e }

  condition:
    any of them
}