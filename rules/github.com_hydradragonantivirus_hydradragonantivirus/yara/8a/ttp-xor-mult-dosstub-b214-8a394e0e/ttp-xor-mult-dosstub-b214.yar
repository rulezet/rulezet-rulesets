rule TTP_XOR_MULT_DOSStub_b214 {
  strings:
    $key_b214 = { e6 7c [2] 92 64 [2] d5 66 [2] 92 77 [2] dc 7b [2] d0 71 [2] c7 7a [2] dc 34 [2] e1 }

  condition:
    any of them
}