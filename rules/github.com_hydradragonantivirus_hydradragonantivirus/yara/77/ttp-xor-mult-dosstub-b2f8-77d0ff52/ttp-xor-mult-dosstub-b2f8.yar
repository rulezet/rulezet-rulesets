rule TTP_XOR_MULT_DOSStub_b2f8 {
  strings:
    $key_b2f8 = { e6 90 [2] 92 88 [2] d5 8a [2] 92 9b [2] dc 97 [2] d0 9d [2] c7 96 [2] dc d8 [2] e1 }

  condition:
    any of them
}