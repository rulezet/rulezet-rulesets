rule TTP_XOR_MULT_DOSStub_3f50 {
  strings:
    $key_3f50 = { 6b 38 [2] 1f 20 [2] 58 22 [2] 1f 33 [2] 51 3f [2] 5d 35 [2] 4a 3e [2] 51 70 [2] 6c }

  condition:
    any of them
}