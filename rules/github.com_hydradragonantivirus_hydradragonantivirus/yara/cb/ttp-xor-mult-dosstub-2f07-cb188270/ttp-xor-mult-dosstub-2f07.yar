rule TTP_XOR_MULT_DOSStub_2f07 {
  strings:
    $key_2f07 = { 7b 6f [2] 0f 77 [2] 48 75 [2] 0f 64 [2] 41 68 [2] 4d 62 [2] 5a 69 [2] 41 27 [2] 7c }

  condition:
    any of them
}