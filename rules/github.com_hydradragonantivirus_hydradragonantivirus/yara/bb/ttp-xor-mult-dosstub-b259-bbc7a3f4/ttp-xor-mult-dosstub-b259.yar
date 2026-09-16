rule TTP_XOR_MULT_DOSStub_b259 {
  strings:
    $key_b259 = { e6 31 [2] 92 29 [2] d5 2b [2] 92 3a [2] dc 36 [2] d0 3c [2] c7 37 [2] dc 79 [2] e1 }

  condition:
    any of them
}