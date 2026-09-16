rule TTP_XOR_MULT_DOSStub_3c11 {
  strings:
    $key_3c11 = { 68 79 [2] 1c 61 [2] 5b 63 [2] 1c 72 [2] 52 7e [2] 5e 74 [2] 49 7f [2] 52 31 [2] 6f }

  condition:
    any of them
}