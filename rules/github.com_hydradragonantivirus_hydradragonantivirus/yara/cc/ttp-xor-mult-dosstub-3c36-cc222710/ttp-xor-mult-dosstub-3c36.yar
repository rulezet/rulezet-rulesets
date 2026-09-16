rule TTP_XOR_MULT_DOSStub_3c36 {
  strings:
    $key_3c36 = { 68 5e [2] 1c 46 [2] 5b 44 [2] 1c 55 [2] 52 59 [2] 5e 53 [2] 49 58 [2] 52 16 [2] 6f }

  condition:
    any of them
}