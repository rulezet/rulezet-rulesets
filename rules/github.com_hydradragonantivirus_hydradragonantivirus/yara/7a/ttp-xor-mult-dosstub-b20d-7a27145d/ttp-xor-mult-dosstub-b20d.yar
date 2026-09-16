rule TTP_XOR_MULT_DOSStub_b20d {
  strings:
    $key_b20d = { e6 65 [2] 92 7d [2] d5 7f [2] 92 6e [2] dc 62 [2] d0 68 [2] c7 63 [2] dc 2d [2] e1 }

  condition:
    any of them
}