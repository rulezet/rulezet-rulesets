rule TTP_XOR_MULT_DOSStub_00e6 {
  strings:
    $key_00e6 = { 54 8e [2] 20 96 [2] 67 94 [2] 20 85 [2] 6e 89 [2] 62 83 [2] 75 88 [2] 6e c6 [2] 53 }

  condition:
    any of them
}