rule TTP_XOR_MULT_DOSStub_050b {
  strings:
    $key_050b = { 51 63 [2] 25 7b [2] 62 79 [2] 25 68 [2] 6b 64 [2] 67 6e [2] 70 65 [2] 6b 2b [2] 56 }

  condition:
    any of them
}