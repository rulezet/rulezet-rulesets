rule TTP_XOR_MULT_DOSStub_2ce0 {
  strings:
    $key_2ce0 = { 78 88 [2] 0c 90 [2] 4b 92 [2] 0c 83 [2] 42 8f [2] 4e 85 [2] 59 8e [2] 42 c0 [2] 7f }

  condition:
    any of them
}