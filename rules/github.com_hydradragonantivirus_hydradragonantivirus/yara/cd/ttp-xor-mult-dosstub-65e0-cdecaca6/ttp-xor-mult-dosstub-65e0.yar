rule TTP_XOR_MULT_DOSStub_65e0 {
  strings:
    $key_65e0 = { 31 88 [2] 45 90 [2] 02 92 [2] 45 83 [2] 0b 8f [2] 07 85 [2] 10 8e [2] 0b c0 [2] 36 }

  condition:
    any of them
}