rule TTP_XOR_MULT_DOSStub_b64f {
  strings:
    $key_b64f = { e2 27 [2] 96 3f [2] d1 3d [2] 96 2c [2] d8 20 [2] d4 2a [2] c3 21 [2] d8 6f [2] e5 }

  condition:
    any of them
}