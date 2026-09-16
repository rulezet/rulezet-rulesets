rule TTP_XOR_MULT_DOSStub_b5ed {
  strings:
    $key_b5ed = { e1 85 [2] 95 9d [2] d2 9f [2] 95 8e [2] db 82 [2] d7 88 [2] c0 83 [2] db cd [2] e6 }

  condition:
    any of them
}