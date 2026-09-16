rule TTP_XOR_MULT_DOSStub_b235 {
  strings:
    $key_b235 = { e6 5d [2] 92 45 [2] d5 47 [2] 92 56 [2] dc 5a [2] d0 50 [2] c7 5b [2] dc 15 [2] e1 }

  condition:
    any of them
}