rule TTP_XOR_MULT_DOSStub_6830 {
  strings:
    $key_6830 = { 3c 58 [2] 48 40 [2] 0f 42 [2] 48 53 [2] 06 5f [2] 0a 55 [2] 1d 5e [2] 06 10 [2] 3b }

  condition:
    any of them
}