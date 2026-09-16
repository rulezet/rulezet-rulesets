rule TTP_XOR_MULT_DOSStub_b56d {
  strings:
    $key_b56d = { e1 05 [2] 95 1d [2] d2 1f [2] 95 0e [2] db 02 [2] d7 08 [2] c0 03 [2] db 4d [2] e6 }

  condition:
    any of them
}