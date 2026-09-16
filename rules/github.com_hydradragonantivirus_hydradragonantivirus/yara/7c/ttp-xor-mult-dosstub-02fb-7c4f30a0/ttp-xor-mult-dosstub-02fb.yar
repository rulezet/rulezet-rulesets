rule TTP_XOR_MULT_DOSStub_02fb {
  strings:
    $key_02fb = { 56 93 [2] 22 8b [2] 65 89 [2] 22 98 [2] 6c 94 [2] 60 9e [2] 77 95 [2] 6c db [2] 51 }

  condition:
    any of them
}