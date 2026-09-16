rule TTP_XOR_MULT_DOSStub_853f {
  strings:
    $key_853f = { d1 57 [2] a5 4f [2] e2 4d [2] a5 5c [2] eb 50 [2] e7 5a [2] f0 51 [2] eb 1f [2] d6 }

  condition:
    any of them
}