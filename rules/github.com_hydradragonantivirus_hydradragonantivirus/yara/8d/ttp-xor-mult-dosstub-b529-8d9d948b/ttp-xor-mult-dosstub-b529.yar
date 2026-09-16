rule TTP_XOR_MULT_DOSStub_b529 {
  strings:
    $key_b529 = { e1 41 [2] 95 59 [2] d2 5b [2] 95 4a [2] db 46 [2] d7 4c [2] c0 47 [2] db 09 [2] e6 }

  condition:
    any of them
}