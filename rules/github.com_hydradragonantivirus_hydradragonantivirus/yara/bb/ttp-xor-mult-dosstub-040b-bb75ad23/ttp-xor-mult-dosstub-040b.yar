rule TTP_XOR_MULT_DOSStub_040b {
  strings:
    $key_040b = { 50 63 [2] 24 7b [2] 63 79 [2] 24 68 [2] 6a 64 [2] 66 6e [2] 71 65 [2] 6a 2b [2] 57 }

  condition:
    any of them
}