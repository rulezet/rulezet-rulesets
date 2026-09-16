rule TTP_XOR_MULT_DOSStub_b21b {
  strings:
    $key_b21b = { e6 73 [2] 92 6b [2] d5 69 [2] 92 78 [2] dc 74 [2] d0 7e [2] c7 75 [2] dc 3b [2] e1 }

  condition:
    any of them
}