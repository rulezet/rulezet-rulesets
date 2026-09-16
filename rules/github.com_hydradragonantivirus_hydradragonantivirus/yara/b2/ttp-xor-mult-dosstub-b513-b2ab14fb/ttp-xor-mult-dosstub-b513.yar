rule TTP_XOR_MULT_DOSStub_b513 {
  strings:
    $key_b513 = { e1 7b [2] 95 63 [2] d2 61 [2] 95 70 [2] db 7c [2] d7 76 [2] c0 7d [2] db 33 [2] e6 }

  condition:
    any of them
}