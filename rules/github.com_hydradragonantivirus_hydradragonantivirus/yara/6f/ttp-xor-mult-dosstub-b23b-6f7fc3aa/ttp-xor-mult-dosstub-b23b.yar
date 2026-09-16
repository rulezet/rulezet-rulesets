rule TTP_XOR_MULT_DOSStub_b23b {
  strings:
    $key_b23b = { e6 53 [2] 92 4b [2] d5 49 [2] 92 58 [2] dc 54 [2] d0 5e [2] c7 55 [2] dc 1b [2] e1 }

  condition:
    any of them
}