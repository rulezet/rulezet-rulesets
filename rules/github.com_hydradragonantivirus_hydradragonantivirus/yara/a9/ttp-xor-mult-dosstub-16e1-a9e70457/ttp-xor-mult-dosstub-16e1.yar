rule TTP_XOR_MULT_DOSStub_16e1 {
  strings:
    $key_16e1 = { 42 89 [2] 36 91 [2] 71 93 [2] 36 82 [2] 78 8e [2] 74 84 [2] 63 8f [2] 78 c1 [2] 45 }

  condition:
    any of them
}