rule TTP_XOR_MULT_DOSStub_b228 {
  strings:
    $key_b228 = { e6 40 [2] 92 58 [2] d5 5a [2] 92 4b [2] dc 47 [2] d0 4d [2] c7 46 [2] dc 08 [2] e1 }

  condition:
    any of them
}