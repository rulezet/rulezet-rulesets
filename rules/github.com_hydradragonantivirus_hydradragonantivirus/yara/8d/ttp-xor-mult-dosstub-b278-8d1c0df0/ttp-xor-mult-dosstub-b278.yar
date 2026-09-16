rule TTP_XOR_MULT_DOSStub_b278 {
  strings:
    $key_b278 = { e6 10 [2] 92 08 [2] d5 0a [2] 92 1b [2] dc 17 [2] d0 1d [2] c7 16 [2] dc 58 [2] e1 }

  condition:
    any of them
}