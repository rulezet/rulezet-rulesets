rule TTP_XOR_MULT_DOSStub_b21f {
  strings:
    $key_b21f = { e6 77 [2] 92 6f [2] d5 6d [2] 92 7c [2] dc 70 [2] d0 7a [2] c7 71 [2] dc 3f [2] e1 }

  condition:
    any of them
}