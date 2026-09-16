rule TTP_XOR_MULT_DOSStub_b26a {
  strings:
    $key_b26a = { e6 02 [2] 92 1a [2] d5 18 [2] 92 09 [2] dc 05 [2] d0 0f [2] c7 04 [2] dc 4a [2] e1 }

  condition:
    any of them
}