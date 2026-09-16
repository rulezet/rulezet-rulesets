rule TTP_XOR_MULT_DOSStub_5f20 {
  strings:
    $key_5f20 = { 0b 48 [2] 7f 50 [2] 38 52 [2] 7f 43 [2] 31 4f [2] 3d 45 [2] 2a 4e [2] 31 00 [2] 0c }

  condition:
    any of them
}