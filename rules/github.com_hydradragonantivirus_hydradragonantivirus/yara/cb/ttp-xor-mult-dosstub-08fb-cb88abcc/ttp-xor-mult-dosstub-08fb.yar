rule TTP_XOR_MULT_DOSStub_08fb {
  strings:
    $key_08fb = { 5c 93 [2] 28 8b [2] 6f 89 [2] 28 98 [2] 66 94 [2] 6a 9e [2] 7d 95 [2] 66 db [2] 5b }

  condition:
    any of them
}