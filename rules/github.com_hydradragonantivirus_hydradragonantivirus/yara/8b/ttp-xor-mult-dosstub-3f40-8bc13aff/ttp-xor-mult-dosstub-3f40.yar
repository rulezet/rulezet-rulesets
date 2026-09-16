rule TTP_XOR_MULT_DOSStub_3f40 {
  strings:
    $key_3f40 = { 6b 28 [2] 1f 30 [2] 58 32 [2] 1f 23 [2] 51 2f [2] 5d 25 [2] 4a 2e [2] 51 60 [2] 6c }

  condition:
    any of them
}