rule TTP_XOR_MULT_DOSStub_b218 {
  strings:
    $key_b218 = { e6 70 [2] 92 68 [2] d5 6a [2] 92 7b [2] dc 77 [2] d0 7d [2] c7 76 [2] dc 38 [2] e1 }

  condition:
    any of them
}