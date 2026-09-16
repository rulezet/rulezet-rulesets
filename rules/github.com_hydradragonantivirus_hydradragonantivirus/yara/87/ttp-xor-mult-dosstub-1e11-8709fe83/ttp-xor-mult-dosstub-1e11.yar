rule TTP_XOR_MULT_DOSStub_1e11 {
  strings:
    $key_1e11 = { 4a 79 [2] 3e 61 [2] 79 63 [2] 3e 72 [2] 70 7e [2] 7c 74 [2] 6b 7f [2] 70 31 [2] 4d }

  condition:
    any of them
}