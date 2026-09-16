rule TTP_XOR_MULT_DOSStub_3f57 {
  strings:
    $key_3f57 = { 6b 3f [2] 1f 27 [2] 58 25 [2] 1f 34 [2] 51 38 [2] 5d 32 [2] 4a 39 [2] 51 77 [2] 6c }

  condition:
    any of them
}