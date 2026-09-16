rule TTP_XOR_MULT_DOSStub_23e0 {
  strings:
    $key_23e0 = { 77 88 [2] 03 90 [2] 44 92 [2] 03 83 [2] 4d 8f [2] 41 85 [2] 56 8e [2] 4d c0 [2] 70 }

  condition:
    any of them
}