rule TTP_XOR_MULT_DOSStub_165b {
  strings:
    $key_165b = { 42 33 [2] 36 2b [2] 71 29 [2] 36 38 [2] 78 34 [2] 74 3e [2] 63 35 [2] 78 7b [2] 45 }

  condition:
    any of them
}