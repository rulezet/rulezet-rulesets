rule TTP_XOR_MULT_DOSStub_b567 {
  strings:
    $key_b567 = { e1 0f [2] 95 17 [2] d2 15 [2] 95 04 [2] db 08 [2] d7 02 [2] c0 09 [2] db 47 [2] e6 }

  condition:
    any of them
}