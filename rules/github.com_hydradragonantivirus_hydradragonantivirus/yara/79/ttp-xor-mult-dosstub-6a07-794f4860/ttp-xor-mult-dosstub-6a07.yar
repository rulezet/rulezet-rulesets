rule TTP_XOR_MULT_DOSStub_6a07 {
  strings:
    $key_6a07 = { 3e 6f [2] 4a 77 [2] 0d 75 [2] 4a 64 [2] 04 68 [2] 08 62 [2] 1f 69 [2] 04 27 [2] 39 }

  condition:
    any of them
}