rule TTP_XOR_MULT_DOSStub_b2fa {
  strings:
    $key_b2fa = { e6 92 [2] 92 8a [2] d5 88 [2] 92 99 [2] dc 95 [2] d0 9f [2] c7 94 [2] dc da [2] e1 }

  condition:
    any of them
}