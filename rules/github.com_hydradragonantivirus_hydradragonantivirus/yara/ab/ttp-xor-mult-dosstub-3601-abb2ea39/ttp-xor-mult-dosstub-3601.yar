rule TTP_XOR_MULT_DOSStub_3601 {
  strings:
    $key_3601 = { 62 69 [2] 16 71 [2] 51 73 [2] 16 62 [2] 58 6e [2] 54 64 [2] 43 6f [2] 58 21 [2] 65 }

  condition:
    any of them
}