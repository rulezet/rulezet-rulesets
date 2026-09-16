rule TTP_XOR_MULT_DOSStub_b269 {
  strings:
    $key_b269 = { e6 01 [2] 92 19 [2] d5 1b [2] 92 0a [2] dc 06 [2] d0 0c [2] c7 07 [2] dc 49 [2] e1 }

  condition:
    any of them
}