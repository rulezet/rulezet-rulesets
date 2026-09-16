rule TTP_XOR_MULT_DOSStub_6821 {
  strings:
    $key_6821 = { 3c 49 [2] 48 51 [2] 0f 53 [2] 48 42 [2] 06 4e [2] 0a 44 [2] 1d 4f [2] 06 01 [2] 3b }

  condition:
    any of them
}