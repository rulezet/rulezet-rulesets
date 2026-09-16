rule TTP_XOR_MULT_DOSStub_2f47 {
  strings:
    $key_2f47 = { 7b 2f [2] 0f 37 [2] 48 35 [2] 0f 24 [2] 41 28 [2] 4d 22 [2] 5a 29 [2] 41 67 [2] 7c }

  condition:
    any of them
}