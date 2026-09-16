rule TTP_XOR_MULT_DOSStub_2f50 {
  strings:
    $key_2f50 = { 7b 38 [2] 0f 20 [2] 48 22 [2] 0f 33 [2] 41 3f [2] 4d 35 [2] 5a 3e [2] 41 70 [2] 7c }

  condition:
    any of them
}