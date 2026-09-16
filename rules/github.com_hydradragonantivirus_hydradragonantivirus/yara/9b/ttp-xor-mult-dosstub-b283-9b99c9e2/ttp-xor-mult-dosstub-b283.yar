rule TTP_XOR_MULT_DOSStub_b283 {
  strings:
    $key_b283 = { e6 eb [2] 92 f3 [2] d5 f1 [2] 92 e0 [2] dc ec [2] d0 e6 [2] c7 ed [2] dc a3 [2] e1 }

  condition:
    any of them
}