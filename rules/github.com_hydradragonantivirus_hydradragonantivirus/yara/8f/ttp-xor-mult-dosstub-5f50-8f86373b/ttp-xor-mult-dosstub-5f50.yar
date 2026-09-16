rule TTP_XOR_MULT_DOSStub_5f50 {
  strings:
    $key_5f50 = { 0b 38 [2] 7f 20 [2] 38 22 [2] 7f 33 [2] 31 3f [2] 3d 35 [2] 2a 3e [2] 31 70 [2] 0c }

  condition:
    any of them
}