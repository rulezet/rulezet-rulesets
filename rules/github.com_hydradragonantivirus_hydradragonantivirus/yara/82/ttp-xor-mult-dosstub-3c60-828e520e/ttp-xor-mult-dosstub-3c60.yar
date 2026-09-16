rule TTP_XOR_MULT_DOSStub_3c60 {
  strings:
    $key_3c60 = { 68 08 [2] 1c 10 [2] 5b 12 [2] 1c 03 [2] 52 0f [2] 5e 05 [2] 49 0e [2] 52 40 [2] 6f }

  condition:
    any of them
}