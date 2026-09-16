rule TTP_XOR_MULT_DOSStub_b51d {
  strings:
    $key_b51d = { e1 75 [2] 95 6d [2] d2 6f [2] 95 7e [2] db 72 [2] d7 78 [2] c0 73 [2] db 3d [2] e6 }

  condition:
    any of them
}