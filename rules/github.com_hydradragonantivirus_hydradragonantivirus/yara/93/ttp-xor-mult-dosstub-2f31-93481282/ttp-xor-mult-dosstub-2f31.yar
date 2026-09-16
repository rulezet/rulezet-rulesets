rule TTP_XOR_MULT_DOSStub_2f31 {
  strings:
    $key_2f31 = { 7b 59 [2] 0f 41 [2] 48 43 [2] 0f 52 [2] 41 5e [2] 4d 54 [2] 5a 5f [2] 41 11 [2] 7c }

  condition:
    any of them
}