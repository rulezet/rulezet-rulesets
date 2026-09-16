rule TTP_XOR_MULT_DOSStub_b208 {
  strings:
    $key_b208 = { e6 60 [2] 92 78 [2] d5 7a [2] 92 6b [2] dc 67 [2] d0 6d [2] c7 66 [2] dc 28 [2] e1 }

  condition:
    any of them
}