rule TTP_XOR_MULT_DOSStub_2507 {
  strings:
    $key_2507 = { 71 6f [2] 05 77 [2] 42 75 [2] 05 64 [2] 4b 68 [2] 47 62 [2] 50 69 [2] 4b 27 [2] 76 }

  condition:
    any of them
}