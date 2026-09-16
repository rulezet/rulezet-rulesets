rule TTP_XOR_MULT_DOSStub_b27a {
  strings:
    $key_b27a = { e6 12 [2] 92 0a [2] d5 08 [2] 92 19 [2] dc 15 [2] d0 1f [2] c7 14 [2] dc 5a [2] e1 }

  condition:
    any of them
}