rule TTP_XOR_MULT_DOSStub_b25f {
  strings:
    $key_b25f = { e6 37 [2] 92 2f [2] d5 2d [2] 92 3c [2] dc 30 [2] d0 3a [2] c7 31 [2] dc 7f [2] e1 }

  condition:
    any of them
}