rule TTP_XOR_MULT_DOSStub_b253 {
  strings:
    $key_b253 = { e6 3b [2] 92 23 [2] d5 21 [2] 92 30 [2] dc 3c [2] d0 36 [2] c7 3d [2] dc 73 [2] e1 }

  condition:
    any of them
}