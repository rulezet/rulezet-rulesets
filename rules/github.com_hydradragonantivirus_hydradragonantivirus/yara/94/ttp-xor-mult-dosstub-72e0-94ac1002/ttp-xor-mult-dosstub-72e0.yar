rule TTP_XOR_MULT_DOSStub_72e0 {
  strings:
    $key_72e0 = { 26 88 [2] 52 90 [2] 15 92 [2] 52 83 [2] 1c 8f [2] 10 85 [2] 07 8e [2] 1c c0 [2] 21 }

  condition:
    any of them
}