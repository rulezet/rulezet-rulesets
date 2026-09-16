rule TTP_XOR_MULT_DOSStub_2f46 {
  strings:
    $key_2f46 = { 7b 2e [2] 0f 36 [2] 48 34 [2] 0f 25 [2] 41 29 [2] 4d 23 [2] 5a 28 [2] 41 66 [2] 7c }

  condition:
    any of them
}