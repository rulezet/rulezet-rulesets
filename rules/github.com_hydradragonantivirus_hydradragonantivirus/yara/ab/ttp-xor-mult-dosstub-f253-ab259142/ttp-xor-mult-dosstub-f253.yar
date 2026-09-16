rule TTP_XOR_MULT_DOSStub_f253 {
  strings:
    $key_f253 = { a6 3b [2] d2 23 [2] 95 21 [2] d2 30 [2] 9c 3c [2] 90 36 [2] 87 3d [2] 9c 73 [2] a1 }

  condition:
    any of them
}