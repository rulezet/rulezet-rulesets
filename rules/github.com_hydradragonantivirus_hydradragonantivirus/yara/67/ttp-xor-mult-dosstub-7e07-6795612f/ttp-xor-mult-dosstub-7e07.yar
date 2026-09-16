rule TTP_XOR_MULT_DOSStub_7e07 {
  strings:
    $key_7e07 = { 2a 6f [2] 5e 77 [2] 19 75 [2] 5e 64 [2] 10 68 [2] 1c 62 [2] 0b 69 [2] 10 27 [2] 2d }

  condition:
    any of them
}