rule TTP_XOR_MULT_DOSStub_6831 {
  strings:
    $key_6831 = { 3c 59 [2] 48 41 [2] 0f 43 [2] 48 52 [2] 06 5e [2] 0a 54 [2] 1d 5f [2] 06 11 [2] 3b }

  condition:
    any of them
}