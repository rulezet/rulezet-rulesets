rule TTP_XOR_MULT_DOSStub_0661 {
  strings:
    $key_0661 = { 52 09 [2] 26 11 [2] 61 13 [2] 26 02 [2] 68 0e [2] 64 04 [2] 73 0f [2] 68 41 [2] 55 }

  condition:
    any of them
}