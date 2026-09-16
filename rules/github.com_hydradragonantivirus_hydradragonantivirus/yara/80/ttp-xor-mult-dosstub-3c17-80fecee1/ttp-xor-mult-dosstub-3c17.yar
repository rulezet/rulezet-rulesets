rule TTP_XOR_MULT_DOSStub_3c17 {
  strings:
    $key_3c17 = { 68 7f [2] 1c 67 [2] 5b 65 [2] 1c 74 [2] 52 78 [2] 5e 72 [2] 49 79 [2] 52 37 [2] 6f }

  condition:
    any of them
}