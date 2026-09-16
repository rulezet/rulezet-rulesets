rule TTP_XOR_MULT_DOSStub_444c {
  strings:
    $key_444c = { 10 24 [2] 64 3c [2] 23 3e [2] 64 2f [2] 2a 23 [2] 26 29 [2] 31 22 [2] 2a 6c [2] 17 }

  condition:
    any of them
}