rule TTP_XOR_MULT_DOSStub_3f31 {
  strings:
    $key_3f31 = { 6b 59 [2] 1f 41 [2] 58 43 [2] 1f 52 [2] 51 5e [2] 5d 54 [2] 4a 5f [2] 51 11 [2] 6c }

  condition:
    any of them
}