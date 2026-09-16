rule TTP_XOR_MULT_DOSStub_f9fb {
  strings:
    $key_f9fb = { ad 93 [2] d9 8b [2] 9e 89 [2] d9 98 [2] 97 94 [2] 9b 9e [2] 8c 95 [2] 97 db [2] aa }

  condition:
    any of them
}