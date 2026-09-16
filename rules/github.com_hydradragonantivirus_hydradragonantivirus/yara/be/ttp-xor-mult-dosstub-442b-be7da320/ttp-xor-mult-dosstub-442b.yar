rule TTP_XOR_MULT_DOSStub_442b {
  strings:
    $key_442b = { 10 43 [2] 64 5b [2] 23 59 [2] 64 48 [2] 2a 44 [2] 26 4e [2] 31 45 [2] 2a 0b [2] 17 }

  condition:
    any of them
}