rule TTP_XOR_MULT_DOSStub_00e7 {
  strings:
    $key_00e7 = { 54 8f [2] 20 97 [2] 67 95 [2] 20 84 [2] 6e 88 [2] 62 82 [2] 75 89 [2] 6e c7 [2] 53 }

  condition:
    any of them
}