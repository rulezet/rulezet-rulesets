rule TTP_XOR_MULT_DOSStub_7207 {
  strings:
    $key_7207 = { 26 6f [2] 52 77 [2] 15 75 [2] 52 64 [2] 1c 68 [2] 10 62 [2] 07 69 [2] 1c 27 [2] 21 }

  condition:
    any of them
}