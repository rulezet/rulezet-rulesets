rule TTP_XOR_MULT_DOSStub_f07b {
  strings:
    $key_f07b = { a4 13 [2] d0 0b [2] 97 09 [2] d0 18 [2] 9e 14 [2] 92 1e [2] 85 15 [2] 9e 5b [2] a3 }

  condition:
    any of them
}