rule TTP_XOR_MULT_DOSStub_1ee0 {
  strings:
    $key_1ee0 = { 4a 88 [2] 3e 90 [2] 79 92 [2] 3e 83 [2] 70 8f [2] 7c 85 [2] 6b 8e [2] 70 c0 [2] 4d }

  condition:
    any of them
}