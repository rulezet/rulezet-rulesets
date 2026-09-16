rule TTP_XOR_MULT_DOSStub_3063 {
  strings:
    $key_3063 = { 64 0b [2] 10 13 [2] 57 11 [2] 10 00 [2] 5e 0c [2] 52 06 [2] 45 0d [2] 5e 43 [2] 63 }

  condition:
    any of them
}