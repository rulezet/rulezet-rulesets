rule TTP_XOR_MULT_DOSStub_3031 {
  strings:
    $key_3031 = { 64 59 [2] 10 41 [2] 57 43 [2] 10 52 [2] 5e 5e [2] 52 54 [2] 45 5f [2] 5e 11 [2] 63 }

  condition:
    any of them
}