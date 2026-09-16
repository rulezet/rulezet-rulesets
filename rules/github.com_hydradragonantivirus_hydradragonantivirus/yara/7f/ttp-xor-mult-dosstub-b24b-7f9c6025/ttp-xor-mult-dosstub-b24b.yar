rule TTP_XOR_MULT_DOSStub_b24b {
  strings:
    $key_b24b = { e6 23 [2] 92 3b [2] d5 39 [2] 92 28 [2] dc 24 [2] d0 2e [2] c7 25 [2] dc 6b [2] e1 }

  condition:
    any of them
}