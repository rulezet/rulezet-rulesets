rule TTP_XOR_MULT_DOSStub_b53f {
  strings:
    $key_b53f = { e1 57 [2] 95 4f [2] d2 4d [2] 95 5c [2] db 50 [2] d7 5a [2] c0 51 [2] db 1f [2] e6 }

  condition:
    any of them
}