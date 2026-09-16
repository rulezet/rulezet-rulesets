rule TTP_XOR_MULT_DOSStub_2f76 {
  strings:
    $key_2f76 = { 7b 1e [2] 0f 06 [2] 48 04 [2] 0f 15 [2] 41 19 [2] 4d 13 [2] 5a 18 [2] 41 56 [2] 7c }

  condition:
    any of them
}