rule TTP_XOR_MULT_DOSStub_b52f {
  strings:
    $key_b52f = { e1 47 [2] 95 5f [2] d2 5d [2] 95 4c [2] db 40 [2] d7 4a [2] c0 41 [2] db 0f [2] e6 }

  condition:
    any of them
}