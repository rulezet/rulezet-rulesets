rule TTP_XOR_MULT_DOSStub_7213 {
  strings:
    $key_7213 = { 26 7b [2] 52 63 [2] 15 61 [2] 52 70 [2] 1c 7c [2] 10 76 [2] 07 7d [2] 1c 33 [2] 21 }

  condition:
    any of them
}