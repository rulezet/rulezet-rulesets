rule TTP_XOR_MULT_DOSStub_2fa3 {
  strings:
    $key_2fa3 = { 7b cb [2] 0f d3 [2] 48 d1 [2] 0f c0 [2] 41 cc [2] 4d c6 [2] 5a cd [2] 41 83 [2] 7c }

  condition:
    any of them
}