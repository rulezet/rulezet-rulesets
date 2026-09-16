rule TTP_XOR_MULT_DOSStub_f061 {
  strings:
    $key_f061 = { a4 09 [2] d0 11 [2] 97 13 [2] d0 02 [2] 9e 0e [2] 92 04 [2] 85 0f [2] 9e 41 [2] a3 }

  condition:
    any of them
}