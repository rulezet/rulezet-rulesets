rule TTP_XOR_MULT_DOSStub_b274 {
  strings:
    $key_b274 = { e6 1c [2] 92 04 [2] d5 06 [2] 92 17 [2] dc 1b [2] d0 11 [2] c7 1a [2] dc 54 [2] e1 }

  condition:
    any of them
}