rule TTP_XOR_MULT_DOSStub_00e0 {
  strings:
    $key_00e0 = { 54 88 [2] 20 90 [2] 67 92 [2] 20 83 [2] 6e 8f [2] 62 85 [2] 75 8e [2] 6e c0 [2] 53 }

  condition:
    any of them
}