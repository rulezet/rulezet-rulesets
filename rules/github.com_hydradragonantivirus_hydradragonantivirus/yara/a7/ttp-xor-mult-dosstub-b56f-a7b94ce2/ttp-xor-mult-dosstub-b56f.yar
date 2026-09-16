rule TTP_XOR_MULT_DOSStub_b56f {
  strings:
    $key_b56f = { e1 07 [2] 95 1f [2] d2 1d [2] 95 0c [2] db 00 [2] d7 0a [2] c0 01 [2] db 4f [2] e6 }

  condition:
    any of them
}