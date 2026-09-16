rule TTP_XOR_MULT_DOSStub_3213 {
  strings:
    $key_3213 = { 66 7b [2] 12 63 [2] 55 61 [2] 12 70 [2] 5c 7c [2] 50 76 [2] 47 7d [2] 5c 33 [2] 61 }

  condition:
    any of them
}