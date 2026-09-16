rule TTP_XOR_MULT_DOSStub_fa83 {
  strings:
    $key_fa83 = { ae eb [2] da f3 [2] 9d f1 [2] da e0 [2] 94 ec [2] 98 e6 [2] 8f ed [2] 94 a3 [2] a9 }

  condition:
    any of them
}