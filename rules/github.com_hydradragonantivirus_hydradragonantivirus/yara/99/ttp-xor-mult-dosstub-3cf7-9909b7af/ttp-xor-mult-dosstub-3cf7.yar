rule TTP_XOR_MULT_DOSStub_3cf7 {
  strings:
    $key_3cf7 = { 68 9f [2] 1c 87 [2] 5b 85 [2] 1c 94 [2] 52 98 [2] 5e 92 [2] 49 99 [2] 52 d7 [2] 6f }

  condition:
    any of them
}