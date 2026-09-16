rule TTP_XOR_MULT_DOSStub_2fa8 {
  strings:
    $key_2fa8 = { 7b c0 [2] 0f d8 [2] 48 da [2] 0f cb [2] 41 c7 [2] 4d cd [2] 5a c6 [2] 41 88 [2] 7c }

  condition:
    any of them
}