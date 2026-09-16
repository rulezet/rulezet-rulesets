rule TTP_XOR_MULT_DOSStub_7c71 {
  strings:
    $key_7c71 = { 28 19 [2] 5c 01 [2] 1b 03 [2] 5c 12 [2] 12 1e [2] 1e 14 [2] 09 1f [2] 12 51 [2] 2f }

  condition:
    any of them
}