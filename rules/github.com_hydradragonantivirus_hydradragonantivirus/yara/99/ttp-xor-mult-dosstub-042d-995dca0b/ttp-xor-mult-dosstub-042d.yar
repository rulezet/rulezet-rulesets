rule TTP_XOR_MULT_DOSStub_042d {
  strings:
    $key_042d = { 50 45 [2] 24 5d [2] 63 5f [2] 24 4e [2] 6a 42 [2] 66 48 [2] 71 43 [2] 6a 0d [2] 57 }

  condition:
    any of them
}