rule TTP_XOR_MULT_DOSStub_7307 {
  strings:
    $key_7307 = { 27 6f [2] 53 77 [2] 14 75 [2] 53 64 [2] 1d 68 [2] 11 62 [2] 06 69 [2] 1d 27 [2] 20 }

  condition:
    any of them
}