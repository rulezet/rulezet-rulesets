rule TTP_XOR_MULT_DOSStub_3013 {
  strings:
    $key_3013 = { 64 7b [2] 10 63 [2] 57 61 [2] 10 70 [2] 5e 7c [2] 52 76 [2] 45 7d [2] 5e 33 [2] 63 }

  condition:
    any of them
}