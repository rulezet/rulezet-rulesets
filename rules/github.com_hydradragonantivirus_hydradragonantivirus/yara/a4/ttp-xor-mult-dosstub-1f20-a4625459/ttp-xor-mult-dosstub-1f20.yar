rule TTP_XOR_MULT_DOSStub_1f20 {
  strings:
    $key_1f20 = { 4b 48 [2] 3f 50 [2] 78 52 [2] 3f 43 [2] 71 4f [2] 7d 45 [2] 6a 4e [2] 71 00 [2] 4c }

  condition:
    any of them
}