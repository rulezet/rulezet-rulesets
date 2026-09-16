rule TTP_XOR_MULT_DOSStub_b26d {
  strings:
    $key_b26d = { e6 05 [2] 92 1d [2] d5 1f [2] 92 0e [2] dc 02 [2] d0 08 [2] c7 03 [2] dc 4d [2] e1 }

  condition:
    any of them
}