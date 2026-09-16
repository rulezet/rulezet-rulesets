rule TTP_XOR_MULT_DOSStub_b203 {
  strings:
    $key_b203 = { e6 6b [2] 92 73 [2] d5 71 [2] 92 60 [2] dc 6c [2] d0 66 [2] c7 6d [2] dc 23 [2] e1 }

  condition:
    any of them
}