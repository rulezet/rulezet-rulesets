rule TTP_XOR_MULT_DOSStub_b202 {
  strings:
    $key_b202 = { e6 6a [2] 92 72 [2] d5 70 [2] 92 61 [2] dc 6d [2] d0 67 [2] c7 6c [2] dc 22 [2] e1 }

  condition:
    any of them
}