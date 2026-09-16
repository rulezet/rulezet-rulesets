rule TTP_XOR_MULT_DOSStub_6de0 {
  strings:
    $key_6de0 = { 39 88 [2] 4d 90 [2] 0a 92 [2] 4d 83 [2] 03 8f [2] 0f 85 [2] 18 8e [2] 03 c0 [2] 3e }

  condition:
    any of them
}