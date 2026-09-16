rule TTP_XOR_MULT_DOSStub_3c71 {
  strings:
    $key_3c71 = { 68 19 [2] 1c 01 [2] 5b 03 [2] 1c 12 [2] 52 1e [2] 5e 14 [2] 49 1f [2] 52 51 [2] 6f }

  condition:
    any of them
}