rule TTP_XOR_MULT_DOSStub_16fb {
  strings:
    $key_16fb = { 42 93 [2] 36 8b [2] 71 89 [2] 36 98 [2] 78 94 [2] 74 9e [2] 63 95 [2] 78 db [2] 45 }

  condition:
    any of them
}