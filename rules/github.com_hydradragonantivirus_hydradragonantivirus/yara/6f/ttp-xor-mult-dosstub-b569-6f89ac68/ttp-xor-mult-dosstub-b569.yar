rule TTP_XOR_MULT_DOSStub_b569 {
  strings:
    $key_b569 = { e1 01 [2] 95 19 [2] d2 1b [2] 95 0a [2] db 06 [2] d7 0c [2] c0 07 [2] db 49 [2] e6 }

  condition:
    any of them
}