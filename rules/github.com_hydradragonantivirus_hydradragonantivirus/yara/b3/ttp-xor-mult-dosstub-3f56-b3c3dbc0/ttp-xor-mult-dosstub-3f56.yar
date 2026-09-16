rule TTP_XOR_MULT_DOSStub_3f56 {
  strings:
    $key_3f56 = { 6b 3e [2] 1f 26 [2] 58 24 [2] 1f 35 [2] 51 39 [2] 5d 33 [2] 4a 38 [2] 51 76 [2] 6c }

  condition:
    any of them
}