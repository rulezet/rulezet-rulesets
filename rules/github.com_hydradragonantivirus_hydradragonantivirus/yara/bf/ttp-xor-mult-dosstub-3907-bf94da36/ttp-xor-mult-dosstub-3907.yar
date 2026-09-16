rule TTP_XOR_MULT_DOSStub_3907 {
  strings:
    $key_3907 = { 6d 6f [2] 19 77 [2] 5e 75 [2] 19 64 [2] 57 68 [2] 5b 62 [2] 4c 69 [2] 57 27 [2] 6a }

  condition:
    any of them
}