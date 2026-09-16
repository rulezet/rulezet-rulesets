rule TTP_XOR_MULT_DOSStub_b23f {
  strings:
    $key_b23f = { e6 57 [2] 92 4f [2] d5 4d [2] 92 5c [2] dc 50 [2] d0 5a [2] c7 51 [2] dc 1f [2] e1 }

  condition:
    any of them
}