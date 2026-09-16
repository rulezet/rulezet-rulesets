rule TTP_XOR_MULT_DOSStub_b22a {
  strings:
    $key_b22a = { e6 42 [2] 92 5a [2] d5 58 [2] 92 49 [2] dc 45 [2] d0 4f [2] c7 44 [2] dc 0a [2] e1 }

  condition:
    any of them
}